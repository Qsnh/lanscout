// Package scan finds the devices on a local IPv4 network and works out what
// they are: their MAC addresses and vendors, their names, the services they
// offer and what kind of device each one is.
//
// It needs no administrator rights and no cgo. Hosts are found with ICMP
// echo and TCP connection attempts, whose replies (or refusals) prove a host
// is there, and with the system's ARP table, which holds every device on the
// segment that answered the ARP requests those probes caused, even phones
// that answer nothing else.
package scan

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Kind is what a device appears to be.
type Kind int

const (
	KindUnknown Kind = iota
	KindRouter
	KindComputer
	KindPhone
	KindTablet
	KindPrinter
	KindCamera
	KindTV
	KindNAS
	KindSpeaker
	KindConsole
	KindIoT
	KindServer
)

var kindLabels = [...]string{
	KindUnknown:  "未知设备",
	KindRouter:   "路由器",
	KindComputer: "电脑",
	KindPhone:    "手机",
	KindTablet:   "平板",
	KindPrinter:  "打印机",
	KindCamera:   "摄像头",
	KindTV:       "电视/盒子",
	KindNAS:      "NAS 存储",
	KindSpeaker:  "智能音箱",
	KindConsole:  "游戏机",
	KindIoT:      "智能家居",
	KindServer:   "服务器",
}

// Label returns the kind's name, in Chinese.
func (k Kind) Label() string {
	if int(k) < len(kindLabels) {
		return kindLabels[k]
	}
	return kindLabels[KindUnknown]
}

// Device is a host found on the network.
type Device struct {
	IP  netip.Addr
	MAC string // "AA:BB:CC:DD:EE:FF", "" when unknown
	// Vendor is the maker registered for the MAC's prefix; RandomMAC that
	// the address is locally administered, as the private addresses phones
	// use on each Wi-Fi network are, so it names no maker.
	Vendor    string
	RandomMAC bool

	// The names the device goes by, from each source.
	DNSName     string // reverse DNS, usually the router's DHCP lease
	MDNSName    string // multicast DNS, as Apple devices and Linux answer
	NetBIOSName string // Windows and Samba hosts
	// UPnP's description of the device, from SSDP.
	UPnPName, UPnPMaker, UPnPModel string
	// Model is the hardware model a device reports over mDNS, e.g.
	// "MacBookPro18,3".
	Model string
	// The title and the Server header of the web page on port 80 or 443.
	HTTPTitle, HTTPServer string

	Ports []int         // open TCP ports, ascending
	RTT   time.Duration // the ICMP or TCP round trip, 0 when unknown

	Kind Kind
	OS   string // a guess: "Windows", "macOS", "iOS", "Android", "Linux"

	IsSelf, IsGateway bool
	// Via lists how the device was found: "ICMP", "TCP", "ARP", "SSDP".
	Via    []string
	SeenAt time.Time
}

// Name returns the device's best name, or "" when it has none.
func (d *Device) Name() string {
	for _, n := range []string{d.MDNSName, d.NetBIOSName, d.DNSName, d.UPnPName} {
		if n != "" {
			return n
		}
	}
	if d.HTTPTitle != "" {
		return d.HTTPTitle
	}
	return ""
}

// HasPort reports whether TCP port p is open.
func (d *Device) HasPort(p int) bool {
	_, ok := slices.BinarySearch(d.Ports, p)
	return ok
}

// Clone returns a copy that shares no slices with d.
func (d *Device) Clone() Device {
	c := *d
	c.Ports = slices.Clone(d.Ports)
	c.Via = slices.Clone(d.Via)
	return c
}

func (d *Device) addVia(v string) {
	if !slices.Contains(d.Via, v) {
		d.Via = append(d.Via, v)
	}
}

func (d *Device) addPort(p int) {
	if i, ok := slices.BinarySearch(d.Ports, p); !ok {
		d.Ports = slices.Insert(d.Ports, i, p)
	}
}

// PortName names the service usually behind TCP port p.
func PortName(p int) string {
	if n, ok := portNames[p]; ok {
		return n
	}
	return ""
}

var portNames = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	53:    "DNS",
	80:    "HTTP",
	135:   "RPC",
	139:   "NetBIOS",
	443:   "HTTPS",
	445:   "SMB 共享",
	515:   "LPD 打印",
	548:   "AFP 共享",
	554:   "RTSP 视频流",
	631:   "IPP 打印",
	1883:  "MQTT",
	3389:  "远程桌面",
	5000:  "UPnP/AirPlay/NAS",
	5001:  "群晖 HTTPS",
	5900:  "VNC",
	7000:  "AirPlay",
	8008:  "Chromecast",
	8009:  "Chromecast",
	8080:  "HTTP 备用",
	8443:  "HTTPS 备用",
	9100:  "打印",
	32400: "Plex",
	62078: "iPhone 同步",
}

// FormatPorts writes ports as "22 SSH, 80 HTTP".
func FormatPorts(ports []int) string {
	var b strings.Builder
	for i, p := range ports {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Itoa(p))
		if n := PortName(p); n != "" {
			b.WriteByte(' ')
			b.WriteString(n)
		}
	}
	return b.String()
}
