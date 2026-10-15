package scan

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// Interface is a network interface with an IPv4 address on a LAN.
type Interface struct {
	Name  string // the system's name: "en0", "WLAN"
	Label string // what people call it: "Wi-Fi", "以太网"
	Index int
	MAC   string
	IP    netip.Addr
	// Prefix is the interface's network, as its mask says, e.g.
	// 192.168.1.0/24.
	Prefix netip.Prefix
	// Gateway is the default route's next hop when it goes through this
	// interface.
	Gateway netip.Addr
	// Virtual marks interfaces of VPNs, virtual machines and containers,
	// listed after the others.
	Virtual bool
}

// String describes the interface, e.g. "Wi-Fi (en0) · 192.168.1.23/24".
func (i Interface) String() string {
	name := i.Name
	if i.Label != "" && i.Label != i.Name {
		name = fmt.Sprintf("%s (%s)", i.Label, i.Name)
	}
	return fmt.Sprintf("%s · %s/%d", name, i.IP, i.Prefix.Bits())
}

// MaxHosts is the most addresses a scan covers: a /20.
const MaxHosts = 4096

// Interfaces lists the interfaces that are up and have an IPv4 address that
// is not a loopback or link-local one, the one of the default route first.
func Interfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	gw, gwIndex := defaultGateway()
	labels := interfaceLabels()
	var out []Interface
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		if skipInterface(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP.To4())
			if !ok || !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			bits, _ := ipn.Mask.Size()
			if bits == 0 || bits > 30 {
				continue
			}
			i := Interface{
				Name:    ifc.Name,
				Label:   labels[ifc.Name],
				Index:   ifc.Index,
				MAC:     NormalizeMAC(ifc.HardwareAddr.String()),
				IP:      ip,
				Prefix:  netip.PrefixFrom(ip, bits).Masked(),
				Virtual: isVirtual(ifc.Name),
			}
			if gw.IsValid() && (gwIndex == ifc.Index || gwIndex == 0 && i.Prefix.Contains(gw)) {
				i.Gateway = gw
			}
			out = append(out, i)
		}
	}
	slices.SortStableFunc(out, func(a, b Interface) int {
		return rank(a) - rank(b)
	})
	if len(out) == 0 {
		return nil, errors.New("没有找到连接到局域网的网卡")
	}
	return out, nil
}

func rank(i Interface) int {
	r := 0
	if !i.Gateway.IsValid() {
		r += 1
	}
	if !i.IP.IsPrivate() {
		r += 2
	}
	if i.Virtual {
		r += 4
	}
	return r
}

// skipInterface leaves out macOS's tunnels and peer-to-peer Wi-Fi.
func skipInterface(name string) bool {
	for _, p := range []string{"utun", "awdl", "llw", "gif", "stf", "anpi", "ap1", "ipsec", "ppp"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func isVirtual(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range []string{"bridge", "vmnet", "vboxnet", "docker", "veth", "vethernet", "virtual", "vmware", "hyper-v", "tailscale", "zerotier", "wsl"} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// ScanPrefix returns the network to scan for an interface: its own, or
// the /24 around its address when its network is larger than MaxHosts.
func ScanPrefix(i Interface) netip.Prefix {
	if hostCount(i.Prefix) <= MaxHosts {
		return i.Prefix
	}
	return netip.PrefixFrom(i.IP, 24).Masked()
}

// ParsePrefix reads a network to scan: "192.168.1.0/24", or an address,
// taken as its /24. The prefix holds at most MaxHosts addresses.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, errors.New("请输入网段，例如 192.168.1.0/24")
	}
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		p, err = netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("网段格式不对：%s", s)
		}
	} else {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("网段格式不对：%s", s)
		}
		p = netip.PrefixFrom(ip, 24)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, errors.New("只支持 IPv4 网段")
	}
	p = p.Masked()
	if hostCount(p) > MaxHosts {
		return netip.Prefix{}, fmt.Errorf("网段太大（/%d），最大支持 /20，即 %d 个地址", p.Bits(), MaxHosts)
	}
	return p, nil
}

// hostCount returns how many addresses p holds, 0 for no prefix.
func hostCount(p netip.Prefix) int {
	if !p.IsValid() || !p.Addr().Is4() {
		return 0
	}
	return 1 << (32 - p.Bits())
}

// Hosts lists the addresses of p that hosts can have: all but the network
// and broadcast addresses, for prefixes shorter than /31. It returns none
// for no prefix.
func Hosts(p netip.Prefix) []netip.Addr {
	p = p.Masked()
	n := hostCount(p)
	out := make([]netip.Addr, 0, n)
	a := p.Addr()
	for i := 0; i < n; i++ {
		if p.Bits() < 31 && (i == 0 || i == n-1) {
			a = a.Next()
			continue
		}
		out = append(out, a)
		a = a.Next()
	}
	return out
}

// Broadcast returns the last address of p.
func Broadcast(p netip.Prefix) netip.Addr {
	if hostCount(p) == 0 {
		return netip.Addr{}
	}
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// interfaceIndex returns the index of the interface named name, 0 for none.
func interfaceIndex(name string) int {
	if name == "" {
		return 0
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0
	}
	return ifc.Index
}
