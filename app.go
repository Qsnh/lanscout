package main

import (
	"cmp"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/Qsnh/lanscout/scan"
)

// app is the state of LanScout's window.
type app struct {
	// post runs fn on the main thread and redraws: the window's Update, or
	// fn at once in tests.
	post func(fn func())
	// historyPath is where devices seen before are kept, "" for nowhere.
	historyPath string
	// save asks where to save a file named name, "" when the user cancels.
	save func(name string) (string, error)
	// toast is a message for the next frame to show.
	toast string

	ifaces   []scan.Interface
	ifaceErr string
	// ifaceLabel is the interface chosen, as the select shows it; network
	// the network to scan, as typed.
	ifaceLabel string
	network    string
	networkErr string

	// The scan going on, or the last one.
	scanning bool
	cancel   context.CancelFunc
	scanID   int
	progress scan.Progress
	started  time.Time
	took     time.Duration
	// iface and prefix are those of the results shown.
	iface   scan.Interface
	prefix  netip.Prefix
	devices map[netip.Addr]scan.Device

	// history holds what was last seen at each address, by network (see
	// historyKey), so that an address in use by a device that is off now
	// is not taken for a free one.
	history map[string]map[netip.Addr]record

	// The view: the table or the map, the search, the sort, the device
	// chosen and whether to list devices seen before but not now.
	page        int
	query       string
	table       ui.ListState
	sort        ui.SortOrder
	row         int
	chosen      netip.Addr
	showOffline bool
}

// record is what the history keeps of a device.
type record struct {
	MAC      string    `json:"mac,omitempty"`
	Name     string    `json:"name,omitempty"`
	Vendor   string    `json:"vendor,omitempty"`
	Kind     scan.Kind `json:"kind"`
	LastSeen time.Time `json:"lastSeen"`
}

func newApp() *app {
	a := &app{
		post:     func(fn func()) { fn() },
		devices:  map[netip.Addr]scan.Device{},
		history:  map[string]map[netip.Addr]record{},
		sort:     ui.SortOrder{Column: colIP},
		row:      -1,
		progress: scan.Progress{Phase: "准备扫描"},
	}
	if dir, err := os.UserConfigDir(); err == nil {
		a.historyPath = filepath.Join(dir, "LanScout", "history.json")
	}
	a.loadInterfaces()
	return a
}

// loadInterfaces reads the interfaces, again before each scan, as the
// computer may have moved to another network or got another address: the
// interface chosen stays chosen, by its name, and the network to scan
// follows it unless the user typed another.
func (a *app) loadInterfaces() {
	old, hadOld := a.chosenInterface()
	ifs, err := scan.Interfaces()
	if err != nil {
		a.ifaces, a.ifaceLabel, a.ifaceErr = nil, "", err.Error()
		return
	}
	a.ifaces, a.ifaceErr = ifs, ""
	pick := ifs[0]
	for _, i := range ifs {
		if hadOld && i.Name == old.Name {
			pick = i
			break
		}
	}
	typed := a.network
	a.chooseInterface(pick.String())
	if hadOld && typed != scan.ScanPrefix(old).String() {
		a.network = typed
	}
}

// chooseInterface makes the interface the select shows as label the one
// to scan from, and its network the one to scan.
func (a *app) chooseInterface(label string) {
	for _, i := range a.ifaces {
		if i.String() == label {
			a.ifaceLabel = label
			a.network = scan.ScanPrefix(i).String()
			a.networkErr = ""
			return
		}
	}
}

func (a *app) interfaceLabels() []string {
	labels := make([]string, len(a.ifaces))
	for i, ifc := range a.ifaces {
		labels[i] = ifc.String()
	}
	return labels
}

func (a *app) chosenInterface() (scan.Interface, bool) {
	for _, i := range a.ifaces {
		if i.String() == a.ifaceLabel {
			return i, true
		}
	}
	return scan.Interface{}, false
}

// startScan scans the network typed from the interface chosen, replacing
// the results shown.
func (a *app) startScan() {
	a.stopScan()
	a.loadInterfaces()
	ifc, ok := a.chosenInterface()
	if !ok {
		a.networkErr = "没有可用的网卡"
		return
	}
	prefix, err := scan.ParsePrefix(a.network)
	if err != nil {
		a.networkErr = err.Error()
		return
	}
	a.networkErr = ""
	a.loadHistory()

	a.scanID++
	id := a.scanID
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.scanning = true
	a.started = time.Now()
	a.took = 0
	a.iface = ifc
	a.prefix = prefix
	a.devices = map[netip.Addr]scan.Device{}
	a.progress = scan.Progress{Phase: "探测在线主机", Total: len(scan.Hosts(prefix))}

	opts := scan.Options{Interface: ifc, Prefix: prefix}
	go func() {
		scan.Run(ctx, opts, scan.Callbacks{
			Progress: func(p scan.Progress) {
				a.post(func() {
					if a.scanID == id {
						a.progress = p
					}
				})
			},
			Device: func(d scan.Device) {
				a.post(func() {
					if a.scanID == id {
						a.devices[d.IP] = d
					}
				})
			},
		})
		a.post(func() {
			if a.scanID != id {
				return
			}
			a.scanning = false
			a.cancel = nil
			a.took = time.Since(a.started)
			if ctx.Err() == nil {
				a.remember()
			}
			cancel()
		})
	}()
}

func (a *app) stopScan() {
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	if a.scanning {
		a.scanning = false
		a.took = time.Since(a.started)
		a.scanID++ // what the canceled scan still sends is stale
	}
}

// entry is a row of the table: a device online now, or one seen at its
// address before.
type entry struct {
	scan.Device
	Offline  bool
	LastSeen time.Time
}

// The IDs of the table's columns.
const (
	colIP     = "ip"
	colName   = "name"
	colKind   = "kind"
	colVendor = "vendor"
	colMAC    = "mac"
	colPorts  = "ports"
	colRTT    = "rtt"
)

// entries returns the rows to show: the devices that match the search,
// sorted as the table says.
func (a *app) entries() []entry {
	var out []entry
	for _, d := range a.devices {
		out = append(out, entry{Device: d, LastSeen: d.SeenAt})
	}
	if a.showOffline {
		for ip, r := range a.seen() {
			if _, online := a.devices[ip]; online || !a.prefix.Contains(ip) {
				continue
			}
			d := scan.Device{IP: ip, MAC: r.MAC, Vendor: r.Vendor, MDNSName: r.Name, Kind: r.Kind, RandomMAC: scan.IsRandomMAC(r.MAC)}
			out = append(out, entry{Device: d, Offline: true, LastSeen: r.LastSeen})
		}
	}
	if q := strings.ToLower(strings.TrimSpace(a.query)); q != "" {
		out = slices.DeleteFunc(out, func(e entry) bool { return !matches(&e.Device, q) })
	}
	slices.SortFunc(out, func(x, y entry) int {
		c := compareBy(a.sort.Column, &x.Device, &y.Device)
		if c == 0 {
			c = x.IP.Compare(y.IP)
		}
		if a.sort.Descending {
			c = -c
		}
		return c
	})
	return out
}

func matches(d *scan.Device, q string) bool {
	fields := []string{d.IP.String(), d.Name(), d.MAC, d.Vendor, scan.Brand(d.Vendor), d.Kind.Label(), d.OS, d.Model, d.UPnPModel, d.HTTPTitle}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	for _, p := range d.Ports {
		if strconv.Itoa(p) == q {
			return true
		}
	}
	return false
}

func compareBy(col string, x, y *scan.Device) int {
	switch col {
	case colName:
		return compareText(x.Name(), y.Name())
	case colKind:
		return cmp.Compare(x.Kind.Label(), y.Kind.Label())
	case colVendor:
		return compareText(scan.Brand(x.Vendor), scan.Brand(y.Vendor))
	case colMAC:
		return compareText(x.MAC, y.MAC)
	case colPorts:
		return cmp.Compare(len(x.Ports), len(y.Ports))
	case colRTT:
		return cmp.Compare(x.RTT, y.RTT)
	}
	return x.IP.Compare(y.IP)
}

// compareText sorts text without regard to case, with empty text last.
func compareText(x, y string) int {
	switch {
	case x == "" && y != "":
		return 1
	case y == "" && x != "":
		return -1
	}
	return cmp.Compare(strings.ToLower(x), strings.ToLower(y))
}

// addressState is what the map shows of an address.
type addressState int

const (
	stateFree addressState = iota
	stateOnline
	stateSelf
	stateGateway
	stateRecent   // offline, but seen at the address before
	stateReserved // the network's and the broadcast address
)

func (a *app) stateOf(ip netip.Addr) addressState {
	if a.prefix.Bits() < 31 && (ip == a.prefix.Addr() || ip == scan.Broadcast(a.prefix)) {
		return stateReserved
	}
	if d, ok := a.devices[ip]; ok {
		switch {
		case d.IsGateway:
			return stateGateway
		case d.IsSelf:
			return stateSelf
		}
		return stateOnline
	}
	if _, ok := a.seen()[ip]; ok {
		return stateRecent
	}
	return stateFree
}

// span is a run of free addresses.
type span struct{ first, last netip.Addr }

func (s span) len() int {
	a, b := s.first.As4(), s.last.As4()
	return int(ipToInt(b) - ipToInt(a) + 1)
}

// String writes the span as "192.168.1.100-192.168.1.199", as routers
// take address pools.
func (s span) String() string {
	if s.first == s.last {
		return s.first.String()
	}
	return s.first.String() + "-" + s.last.String()
}

// label writes the span for people: "192.168.1.100 – 199", the last
// address without the octets it shares with the first.
func (s span) label() string {
	if s.first == s.last {
		return s.first.String()
	}
	a, b := s.first.As4(), s.last.As4()
	i := 0
	for i < 3 && a[i] == b[i] {
		i++
	}
	parts := make([]string, 0, 4-i)
	for _, o := range b[i:] {
		parts = append(parts, strconv.Itoa(int(o)))
	}
	return s.first.String() + " – " + strings.Join(parts, ".")
}

func ipToInt(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// freeSpans returns the runs of free addresses, the longest first.
func (a *app) freeSpans() []span {
	var spans []span
	var cur *span
	for _, ip := range scan.Hosts(a.prefix) {
		if a.stateOf(ip) == stateFree {
			if cur == nil {
				spans = append(spans, span{ip, ip})
				cur = &spans[len(spans)-1]
			} else {
				cur.last = ip
			}
		} else {
			cur = nil
		}
	}
	slices.SortStableFunc(spans, func(x, y span) int { return y.len() - x.len() })
	return spans
}

// counts returns how many devices are online, how many addresses are
// free, and how many were in use before.
func (a *app) counts() (online, free, recent int) {
	if !a.prefix.IsValid() {
		return 0, 0, 0
	}
	for _, ip := range scan.Hosts(a.prefix) {
		switch a.stateOf(ip) {
		case stateFree:
			free++
		case stateRecent:
			recent++
		}
	}
	return len(a.devices), free, recent
}

// historyKey names the network shown in the history: its prefix and its
// gateway's MAC address, as two networks, at home and at work, may both be
// 192.168.1.0/24. It is "" until the gateway is found.
func (a *app) historyKey() string {
	if !a.prefix.IsValid() {
		return ""
	}
	gw := a.iface.Gateway
	if !gw.IsValid() || !a.prefix.Contains(gw) {
		return a.prefix.String()
	}
	if d, ok := a.devices[gw]; ok && d.MAC != "" {
		return a.prefix.String() + " " + d.MAC
	}
	return ""
}

// seen returns what the history holds of the network shown, nil for
// nothing.
func (a *app) seen() map[netip.Addr]record {
	if key := a.historyKey(); key != "" {
		return a.history[key]
	}
	return nil
}

func (a *app) loadHistory() {
	if a.historyPath == "" {
		return
	}
	b, err := os.ReadFile(a.historyPath)
	if err != nil {
		return
	}
	var h map[string]map[netip.Addr]record
	if json.Unmarshal(b, &h) == nil && h != nil {
		a.history = h
	}
}

// remember adds the devices of a finished scan to the history, which keeps
// each address for 30 days after it was last seen in use.
func (a *app) remember() {
	key := a.historyKey()
	if key == "" {
		return
	}
	h := a.history[key]
	if h == nil {
		h = map[netip.Addr]record{}
		a.history[key] = h
	}
	for ip, d := range a.devices {
		h[ip] = record{MAC: d.MAC, Name: d.Name(), Vendor: d.Vendor, Kind: d.Kind, LastSeen: d.SeenAt}
	}
	for ip, r := range h {
		if time.Since(r.LastSeen) > 30*24*time.Hour {
			delete(h, ip)
		}
	}
	a.saveHistory()
}

// forget clears the history of the network shown.
func (a *app) forget() {
	delete(a.history, a.historyKey())
	a.saveHistory()
}

// saveHistory writes the history to a file beside it, then puts it in its
// place, so that a crash while writing leaves the last one whole.
func (a *app) saveHistory() {
	if a.historyPath == "" {
		return
	}
	b, err := json.MarshalIndent(a.history, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(a.historyPath), 0o755)
	tmp := a.historyPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	os.Rename(tmp, a.historyPath)
}

// export asks where to save the scan as a CSV table, and saves it there.
func (a *app) export() {
	if !a.prefix.IsValid() || a.save == nil {
		a.toast = "还没有可导出的扫描结果"
		return
	}
	name := fmt.Sprintf("LanScout %s %s.csv", strings.ReplaceAll(a.prefix.String(), "/", "_"), time.Now().Format("2006-01-02 1504"))
	go func() {
		path, err := a.save(name)
		if err != nil || path == "" {
			return
		}
		a.post(func() {
			if err := a.writeCSV(path); err != nil {
				a.toast = "导出失败：" + err.Error()
			} else {
				a.toast = "已导出到 " + filepath.Base(path)
			}
		})
	}()
}

// writeCSV writes every address of the network, in use or free, for a
// spreadsheet: UTF-8 with a byte order mark, which Excel needs to read
// Chinese.
func (a *app) writeCSV(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	f.WriteString("\xEF\xBB\xBF")
	w := csv.NewWriter(f)
	w.Write([]string{"IP 地址", "状态", "设备名称", "类型", "系统", "厂商", "MAC 地址", "随机 MAC", "开放端口", "延迟 (ms)", "型号", "网页标题", "发现方式", "最后在线"})
	history := a.seen()
	for _, ip := range scan.Hosts(a.prefix) {
		row := []string{ip.String()}
		d, online := a.devices[ip]
		r, seen := history[ip]
		switch {
		case online:
			status := "在线"
			if d.IsGateway {
				status = "在线 (网关)"
			} else if d.IsSelf {
				status = "在线 (本机)"
			}
			rtt := ""
			if d.RTT > 0 {
				rtt = fmt.Sprintf("%.1f", float64(d.RTT.Microseconds())/1000)
			}
			model := d.Model
			if model == "" {
				model = d.UPnPModel
			}
			row = append(row, status, d.Name(), d.Kind.Label(), d.OS, scan.Brand(d.Vendor), d.MAC, yesNo(d.RandomMAC), scan.FormatPorts(d.Ports), rtt, model, d.HTTPTitle, strings.Join(d.Via, " "), d.SeenAt.Format("2006-01-02 15:04"))
		case seen:
			row = append(row, "离线 (曾使用)", r.Name, r.Kind.Label(), "", scan.Brand(r.Vendor), r.MAC, yesNo(scan.IsRandomMAC(r.MAC)), "", "", "", "", "", r.LastSeen.Format("2006-01-02 15:04"))
		default:
			row = append(row, "空闲", "", "", "", "", "", "", "", "", "", "", "", "")
		}
		w.Write(row)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func yesNo(b bool) string {
	if b {
		return "是"
	}
	return "否"
}
