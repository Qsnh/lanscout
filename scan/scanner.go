package scan

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync"
	"time"
)

// Options say what to scan.
type Options struct {
	// Interface is the local interface on the network; Prefix the
	// addresses to scan, its network by default.
	Interface Interface
	Prefix    netip.Prefix
	// Timeout bounds each probe of the sweep: 800 ms by default.
	Timeout time.Duration
	// Workers is how many hosts are probed at once: 64 by default.
	Workers int
}

// Progress tells how far a scan has come.
type Progress struct {
	Phase       string // what the scan is doing, in Chinese
	Done, Total int
	// Fraction is the share of the whole scan done, from 0 to 1.
	Fraction float64
}

// Callbacks receive a scan's findings as they come, from its goroutines.
type Callbacks struct {
	Progress func(Progress)
	// Device receives a device as soon as it is found, then again each
	// time more is known of it, one call at a time: it must not block. It
	// owns the copy it gets.
	Device func(Device)
}

// sweepPorts are tried on every address, as most computers, routers and
// phones keep one of them open or refuse it, which proves them there.
var sweepPorts = []int{80, 443, 22, 445, 139, 62078, 8080, 7000}

// servicePorts are tried on the hosts found, to tell what they are.
var servicePorts = []int{21, 22, 23, 53, 80, 135, 139, 443, 445, 515, 548, 554, 631, 1883, 3389, 5000, 5001, 5900, 7000, 8008, 8009, 8080, 8443, 9100, 32400, 62078}

// Run scans the network: it sweeps every address with ICMP echo and TCP
// connections, adds the hosts the ARP table learnt meanwhile, then asks
// each host found for its names and services. It returns the devices
// found, sorted by address, when done or when ctx is canceled.
func Run(ctx context.Context, opts Options, cb Callbacks) []Device {
	if !opts.Prefix.IsValid() {
		opts.Prefix = ScanPrefix(opts.Interface)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 800 * time.Millisecond
	}
	if opts.Workers <= 0 {
		opts.Workers = 64
	}
	if cb.Progress == nil {
		cb.Progress = func(Progress) {}
	}
	if cb.Device == nil {
		cb.Device = func(Device) {}
	}
	s := &scanner{opts: opts, cb: cb, devices: map[netip.Addr]*Device{}}
	return s.run(ctx)
}

type scanner struct {
	opts Options
	cb   Callbacks

	mu      sync.Mutex
	devices map[netip.Addr]*Device
}

// update changes the device at ip, adding it if new, and sends the result
// to the callback.
func (s *scanner) update(ip netip.Addr, fn func(d *Device)) {
	s.mu.Lock()
	d, ok := s.devices[ip]
	if !ok {
		d = &Device{IP: ip}
		s.devices[ip] = d
	}
	fn(d)
	d.SeenAt = time.Now()
	if d.MAC != "" && d.Vendor == "" {
		d.Vendor = Vendor(d.MAC)
		d.RandomMAC = IsRandomMAC(d.MAC)
	}
	d.IsSelf = ip == s.opts.Interface.IP
	d.IsGateway = ip == s.opts.Interface.Gateway
	Classify(d)
	if d.IsSelf {
		d.OS = localOS()
	}
	// Sent under the lock, so that the callback gets a device's copies in
	// the order they were made, the last one last.
	s.cb.Device(d.Clone())
	s.mu.Unlock()
}

func (s *scanner) found() []netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	ips := make([]netip.Addr, 0, len(s.devices))
	for ip := range s.devices {
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
	return ips
}

func (s *scanner) run(ctx context.Context) []Device {
	self := s.opts.Interface
	prefix := s.opts.Prefix
	hosts := Hosts(prefix)

	if prefix.Contains(self.IP) {
		host, _ := os.Hostname()
		s.update(self.IP, func(d *Device) {
			d.MAC = self.MAC
			d.MDNSName = cleanHostname(host, self.IP)
			d.addVia("本机")
		})
	}

	// SSDP answers come while the sweep goes on.
	var ssdp map[netip.Addr]upnpDevice
	ssdpDone := make(chan struct{})
	go func() {
		defer close(ssdpDone)
		ssdp = discoverSSDP(ctx, self, prefix, 3*time.Second)
	}()

	s.sweep(ctx, hosts)

	<-ssdpDone
	for ip, u := range ssdp {
		s.update(ip, func(d *Device) {
			d.UPnPName, d.UPnPMaker, d.UPnPModel = u.Name, u.Maker, u.Model
			if d.HTTPServer == "" {
				d.HTTPServer = u.Server
			}
			d.addVia("SSDP")
		})
	}
	// Replies to the last probes may still be on their way.
	if ctx.Err() == nil {
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
		}
	}
	s.readARP(prefix)

	if ctx.Err() == nil {
		s.identify(ctx, s.found())
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Device, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, d.Clone())
	}
	slices.SortFunc(out, func(a, b Device) int { return a.IP.Compare(b.IP) })
	return out
}

// sweep probes every address, sending the hosts that answer to the
// callback, and reads the ARP table every second for those that answer
// only ARP.
func (s *scanner) sweep(ctx context.Context, hosts []netip.Addr) {
	ping, err := newPinger()
	if err != nil {
		ping = noPinger{}
	}
	defer ping.Close()

	total := len(hosts)
	var done int
	var doneMu sync.Mutex
	report := func() {
		doneMu.Lock()
		done++
		n := done
		doneMu.Unlock()
		if n%4 == 0 || n == total {
			s.cb.Progress(Progress{Phase: "探测在线主机", Done: n, Total: total, Fraction: 0.7 * float64(n) / float64(total)})
		}
	}
	s.cb.Progress(Progress{Phase: "探测在线主机", Total: total})

	stopARP := make(chan struct{})
	arpDone := make(chan struct{})
	go func() {
		defer close(arpDone)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.readARP(s.opts.Prefix)
			case <-stopARP:
				return
			}
		}
	}()

	jobs := make(chan netip.Addr)
	var wg sync.WaitGroup
	for range min(s.opts.Workers, total) {
		wg.Go(func() {
			for ip := range jobs {
				if ip != s.opts.Interface.IP {
					s.probe(ctx, ping, ip)
				}
				report()
			}
		})
	}
feed:
	for _, ip := range hosts {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	close(stopARP)
	<-arpDone
}

// probe pings ip and tries the sweep's ports at once, and stops at the first
// answer.
func (s *scanner) probe(ctx context.Context, ping pinger, ip netip.Addr) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type answer struct {
		via  string
		port int // an open port, 0 for none
		rtt  time.Duration
	}
	answers := make(chan answer, len(sweepPorts)+1)
	var wg sync.WaitGroup
	wg.Go(func() {
		// Twice, for a reply lost on Wi-Fi or a host waking up.
		for range 2 {
			if rtt, ok := ping.Ping(ctx, ip, s.opts.Timeout); ok {
				answers <- answer{"ICMP", 0, rtt}
				return
			}
			if ctx.Err() != nil {
				return
			}
		}
	})
	for _, port := range sweepPorts {
		wg.Go(func() {
			if open, alive, rtt := dialTCP(ctx, ip, port, s.opts.Timeout); alive {
				if !open {
					port = 0
				}
				answers <- answer{"TCP", port, rtt}
			}
		})
	}
	go func() {
		wg.Wait()
		close(answers)
	}()
	for a := range answers {
		s.update(ip, func(d *Device) {
			d.addVia(a.via)
			if a.port != 0 {
				d.addPort(a.port)
			}
			if a.via == "ICMP" || d.RTT == 0 {
				d.RTT = a.rtt
			}
		})
		// The host is there: the rest of the sweep's answers would tell
		// no more than identify will.
		cancel()
	}
}

// readARP adds the hosts of the system's ARP table that are on the network,
// and the MAC addresses of those found.
func (s *scanner) readARP(prefix netip.Prefix) {
	entries, err := readARP()
	if err != nil {
		return
	}
	for _, e := range entries {
		if !prefix.Contains(e.IP) || e.IP == Broadcast(prefix) {
			continue
		}
		s.mu.Lock()
		d := s.devices[e.IP]
		known := d != nil && d.MAC == e.MAC && slices.Contains(d.Via, "ARP")
		s.mu.Unlock()
		if known {
			continue
		}
		s.update(e.IP, func(d *Device) {
			if d.MAC != e.MAC {
				d.MAC, d.Vendor = e.MAC, ""
			}
			d.addVia("ARP")
		})
	}
}

// identify asks each host for its names and tries the service ports, a few
// hosts at a time.
func (s *scanner) identify(ctx context.Context, ips []netip.Addr) {
	total := len(ips)
	var done int
	var mu sync.Mutex
	s.cb.Progress(Progress{Phase: "识别设备", Total: total, Fraction: 0.7})
	jobs := make(chan netip.Addr)
	var wg sync.WaitGroup
	for range min(16, max(total, 1)) {
		wg.Go(func() {
			for ip := range jobs {
				s.identifyHost(ctx, ip)
				mu.Lock()
				done++
				n := done
				mu.Unlock()
				s.cb.Progress(Progress{Phase: "识别设备", Done: n, Total: total, Fraction: 0.7 + 0.3*float64(n)/float64(total)})
			}
		})
	}
feed:
	for _, ip := range ips {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
}

func (s *scanner) identifyHost(ctx context.Context, ip netip.Addr) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var ports []int
	var rtt time.Duration
	for _, port := range servicePorts {
		wg.Go(func() {
			if open, _, t := dialTCP(ctx, ip, port, s.opts.Timeout); open {
				mu.Lock()
				ports = append(ports, port)
				if rtt == 0 || t < rtt {
					rtt = t
				}
				mu.Unlock()
			}
		})
	}
	var dnsName, nbName, mdnsName, model string
	wg.Go(func() { dnsName = reverseDNS(ctx, ip) })
	wg.Go(func() { nbName = netbiosName(ctx, ip) })
	wg.Go(func() { mdnsName, model = mdnsInfo(ctx, ip) })
	wg.Wait()
	slices.Sort(ports)

	// The home page of a web server names many a router, printer or camera.
	var title, server string
	for _, p := range []int{80, 8080, 443, 8443, 5000} {
		if _, ok := slices.BinarySearch(ports, p); ok {
			if title, server = webInfo(ctx, ip, p); title != "" || server != "" {
				break
			}
		}
	}

	if ctx.Err() != nil {
		return
	}
	s.update(ip, func(d *Device) {
		for _, p := range ports {
			d.addPort(p)
		}
		if d.RTT == 0 {
			d.RTT = rtt
		}
		if dnsName != "" {
			d.DNSName = dnsName
		}
		if nbName != "" {
			d.NetBIOSName = nbName
		}
		if mdnsName != "" {
			d.MDNSName = mdnsName
		}
		if model != "" {
			d.Model = model
		}
		if title != "" {
			d.HTTPTitle = title
		}
		if server != "" {
			d.HTTPServer = server
		}
	})
}

func localOS() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	}
	return runtime.GOOS
}
