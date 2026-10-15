package main

import (
	"image/png"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/Qsnh/lanscout/scan"
)

// testApp is an app that has scanned a network of a router, this
// computer, a phone, a printer and a smart plug, and saw a laptop before.
func testApp() *app {
	prefix := netip.MustParsePrefix("192.168.3.0/24")
	ifc := scan.Interface{Name: "en0", Label: "Wi-Fi", IP: netip.MustParseAddr("192.168.3.12"), Prefix: prefix, Gateway: netip.MustParseAddr("192.168.3.1")}
	a := &app{
		post:       func(fn func()) { fn() },
		ifaces:     []scan.Interface{ifc},
		ifaceLabel: ifc.String(),
		network:    prefix.String(),
		iface:      ifc,
		prefix:     prefix,
		devices:    map[netip.Addr]scan.Device{},
		history:    map[string]map[netip.Addr]record{},
		sort:       ui.SortOrder{Column: colIP},
		row:        -1,
		took:       8600 * time.Millisecond,
		started:    time.Date(2026, 10, 14, 16, 40, 0, 0, time.Local),
	}
	now := time.Now()
	add := func(d scan.Device) {
		d.IsGateway = d.IP == ifc.Gateway
		d.IsSelf = d.IP == ifc.IP
		d.SeenAt = now
		if d.MAC != "" {
			d.Vendor = scan.Vendor(d.MAC)
			d.RandomMAC = scan.IsRandomMAC(d.MAC)
		}
		scan.Classify(&d)
		a.devices[d.IP] = d
	}
	ip := netip.MustParseAddr
	add(scan.Device{IP: ip("192.168.3.1"), MAC: "58:F2:FC:10:20:01", UPnPName: "华为路由 AX2 Pro", Ports: []int{53, 80, 443}, RTT: 15 * time.Millisecond, Via: []string{"ICMP", "ARP", "SSDP"}})
	add(scan.Device{IP: ip("192.168.3.12"), MAC: "32:BF:8F:10:20:12", MDNSName: "Studio", Ports: []int{5900, 7000}, Via: []string{"本机"}})
	add(scan.Device{IP: ip("192.168.3.16"), MAC: "BE:B5:85:10:20:16", MDNSName: "Adas-iPhone", Ports: []int{62078}, RTT: 110 * time.Millisecond, Via: []string{"ICMP", "ARP"}})
	add(scan.Device{IP: ip("192.168.3.27"), MAC: "A4:46:B4:10:20:27", Ports: []int{80, 515, 631, 9100}, RTT: 160 * time.Millisecond, Via: []string{"ICMP", "ARP"}})
	add(scan.Device{IP: ip("192.168.3.32"), MAC: "C0:39:37:10:20:32", RTT: 140 * time.Millisecond, Via: []string{"ICMP", "ARP"}})
	a.history[a.historyKey()] = map[netip.Addr]record{
		ip("192.168.3.50"): {MAC: "3C:22:FB:00:11:22", Name: "Ada-MacBook-Air", Vendor: "Apple", Kind: scan.KindComputer, LastSeen: now.Add(-26 * time.Hour)},
	}
	return a
}

func TestTable(t *testing.T) {
	a := testApp()
	tt := ui.NewTester(a.view, 1240, 800)
	tt.SetLocale("zh-Hans")
	for _, s := range []string{"192.168.3.1", "华为路由 AX2 Pro", "Adas-iPhone", "打印机", "路由器", "手机", "智能家居", "格力 Gree"} {
		if !tt.HasText(s) {
			t.Errorf("no %q in the table: %q", s, tt.Texts())
		}
	}
	// 254 addresses, 5 online, 1 seen before.
	if !tt.HasText("248") {
		t.Errorf("free addresses not 248: %q", tt.Texts())
	}
	if tt.HasText("Ada-MacBook-Air") {
		t.Error("an offline device shows without 显示离线设备")
	}
	if err := tt.Click("显示离线设备"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("Ada-MacBook-Air") || !tt.HasText("离线") {
		t.Errorf("no offline device after checking 显示离线设备: %q", tt.Texts())
	}

	// Choosing a row shows the device's details.
	if err := tt.Click("Adas-iPhone"); err != nil {
		t.Fatal(err)
	}
	if a.chosen != netip.MustParseAddr("192.168.3.16") {
		t.Fatalf("chosen %v after clicking the phone", a.chosen)
	}
	if !tt.HasText("iPhone 同步") || !tt.HasText("复制 MAC") {
		t.Errorf("no details of the phone: %q", tt.Texts())
	}
	saveImage(t, tt, "table.png")
	if err := tt.Click("复制 IP"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if got := tt.Clipboard(); got != "192.168.3.16" {
		t.Errorf("clipboard %q after 复制 IP", got)
	}

	// The search narrows the rows.
	a.query = "打印"
	tt.Frame()
	if rows := a.entries(); len(rows) != 1 || rows[0].IP != netip.MustParseAddr("192.168.3.27") {
		t.Errorf("search 打印 finds %v", rows)
	}
}

func TestAddressMap(t *testing.T) {
	a := testApp()
	tt := ui.NewTester(a.view, 1240, 800)
	tt.SetLocale("zh-Hans")
	if err := tt.Click("IP 分布图"); err != nil {
		t.Fatal(err)
	}
	if a.page != pageMap {
		t.Fatalf("page %d after clicking IP 分布图", a.page)
	}
	// The longest free run is 192.168.3.51 – 192.168.3.254.
	if !tt.HasText("192.168.3.51 – 254") || !tt.HasText("204 个") {
		t.Errorf("free runs: %q", tt.Texts())
	}
	// A click on one in use chooses its device.
	if err := tt.Click("27"); err != nil {
		t.Fatal(err)
	}
	if a.chosen != netip.MustParseAddr("192.168.3.27") {
		t.Errorf("chosen %v after clicking 27", a.chosen)
	}
	saveImage(t, tt, "map.png")
	tt.SetDark(true)
	tt.Frame()
	saveImage(t, tt, "map-dark.png")

	// A click on a free address copies it.
	if err := tt.Click("100"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if got := tt.Clipboard(); got != "192.168.3.100" {
		t.Errorf("clipboard %q after clicking a free address", got)
	}
}

func TestExportCSV(t *testing.T) {
	a := testApp()
	path := filepath.Join(t.TempDir(), "scan.csv")
	if err := a.writeCSV(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.HasPrefix(s, "\xEF\xBB\xBF") {
		t.Error("no byte order mark")
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) != 255 {
		t.Errorf("%d lines, want a header and 254 addresses", len(lines))
	}
	for _, want := range []string{"192.168.3.1,在线 (网关),华为路由 AX2 Pro", "192.168.3.50,离线 (曾使用),Ada-MacBook-Air", "192.168.3.100,空闲"} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q in the CSV", want)
		}
	}
}

// The history of a network is that of its gateway too: another network
// numbered alike, behind another router, has none of it.
func TestHistoryByGateway(t *testing.T) {
	a := testApp()
	if _, free, recent := a.counts(); free != 248 || recent != 1 {
		t.Fatalf("free %d, recent %d", free, recent)
	}
	gw := a.devices[a.iface.Gateway]
	gw.MAC = "00:11:22:33:44:55"
	a.devices[gw.IP] = gw
	if _, free, recent := a.counts(); free != 249 || recent != 0 {
		t.Errorf("behind another router: free %d, recent %d", free, recent)
	}

	// Saved and read back.
	a = testApp()
	a.historyPath = filepath.Join(t.TempDir(), "LanScout", "history.json")
	a.remember()
	b := testApp()
	b.history = map[string]map[netip.Addr]record{}
	b.historyPath = a.historyPath
	b.loadHistory()
	if got := len(b.seen()); got != 6 {
		t.Errorf("%d addresses in the history read back, want 6", got)
	}
}

// Without a network, as before the first scan or without any interface,
// the view shows no addresses.
func TestNoNetwork(t *testing.T) {
	a := testApp()
	a.prefix, a.iface, a.devices, a.took = netip.Prefix{}, scan.Interface{}, map[netip.Addr]scan.Device{}, 0
	a.ifaces, a.ifaceLabel, a.ifaceErr = nil, "", "没有找到连接到局域网的网卡"
	tt := ui.NewTester(a.view, 1240, 800)
	tt.SetLocale("zh-Hans")
	if !tt.HasText("重新检测") {
		t.Errorf("no retry: %q", tt.Texts())
	}
	a.page = pageMap
	tt.Frame()
	if len(a.freeSpans()) != 0 {
		t.Error("free spans without a network")
	}
}

func TestStaleScanResults(t *testing.T) {
	a := testApp()
	a.scanID = 7
	a.scanning = true
	a.stopScan()
	if a.scanning || a.scanID == 7 {
		t.Errorf("scanning %v, id %d after stopping", a.scanning, a.scanID)
	}
}

// saveImage writes the frame to $LANSCOUT_SHOTS, to look at.
func saveImage(t *testing.T, tt *ui.Tester, name string) {
	dir := os.Getenv("LANSCOUT_SHOTS")
	if dir == "" {
		return
	}
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, tt.Image()); err != nil {
		t.Fatal(err)
	}
}
