package scan

import (
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseARP(t *testing.T) {
	macOS := `? (192.168.3.1) at 58:f2:fc:10:20:01 on en1 ifscope [ethernet]
? (192.168.3.3) at d6:fa:bb:10:20:03 on en1 ifscope [ethernet]
? (192.168.3.77) at (incomplete) on en1 ifscope [ethernet]
? (192.168.3.255) at ff:ff:ff:ff:ff:ff on en1 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en1 ifscope permanent [ethernet]
? (192.168.3.16) at be:b5:85:10:20:6 on en1 ifscope [ethernet]
`
	windows := "\r\n接口: 192.168.3.12 --- 0xb\r\n" +
		"  Internet 地址         物理地址              类型\r\n" +
		"  192.168.3.1           58-f2-fc-10-20-01     动态\r\n" +
		"  192.168.3.27          a4-46-b4-10-20-27     动态\r\n" +
		"  192.168.3.255         ff-ff-ff-ff-ff-ff     静态\r\n" +
		"  224.0.0.22            01-00-5e-00-00-16     静态\r\n"
	linux := `IP address       HW type     Flags       HW address            Mask     Device
192.168.3.1      0x1         0x2         58:f2:fc:10:20:01     *        wlan0
192.168.3.9      0x1         0x0         00:00:00:00:00:00     *        wlan0
`
	for _, tc := range []struct {
		name, out string
		want      []arpEntry
	}{
		{"macOS", macOS, []arpEntry{
			{netip.MustParseAddr("192.168.3.1"), "58:F2:FC:10:20:01"},
			{netip.MustParseAddr("192.168.3.3"), "D6:FA:BB:10:20:03"},
			{netip.MustParseAddr("192.168.3.16"), "BE:B5:85:10:20:06"},
		}},
		{"Windows", windows, []arpEntry{
			{netip.MustParseAddr("192.168.3.1"), "58:F2:FC:10:20:01"},
			{netip.MustParseAddr("192.168.3.27"), "A4:46:B4:10:20:27"},
		}},
		{"Linux", linux, []arpEntry{
			{netip.MustParseAddr("192.168.3.1"), "58:F2:FC:10:20:01"},
		}},
	} {
		if got := parseARP(tc.out); !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestVendor(t *testing.T) {
	for mac, want := range map[string]string{
		"F0:18:98:00:00:01": "苹果 Apple",
		"58:F2:FC:10:20:01": "华为 Huawei",
		"04:AE:47:10:20:02": "小米 Xiaomi",
		"3C:84:6A:00:00:00": "普联 TP-Link",
		"64:F0:AD:10:20:18": "天猫精灵 Tmall Genie",
		"D6:FA:BB:10:20:03": "", // random
	} {
		if got := Brand(Vendor(mac)); got != want {
			t.Errorf("Brand(Vendor(%s)) = %q, want %q", mac, got, want)
		}
	}
	if !IsRandomMAC("D6:FA:BB:10:20:03") || IsRandomMAC("58:F2:FC:10:20:01") {
		t.Error("IsRandomMAC is wrong")
	}
	// "intel" within a word is not Intel.
	if got := Brand("Intellicheck Mobilisa"); got != "Intellicheck Mobilisa" {
		t.Errorf("Brand(Intellicheck) = %q", got)
	}
}

func TestParsePrefix(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.1.0/24":  "192.168.1.0/24",
		"192.168.1.77/24": "192.168.1.0/24",
		"10.0.5.9":        "10.0.5.0/24",
		"172.16.0.0/20":   "172.16.0.0/20",
	} {
		p, err := ParsePrefix(in)
		if err != nil || p.String() != want {
			t.Errorf("ParsePrefix(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	for _, in := range []string{"", "10.0.0.0/8", "fe80::/64", "192.168.1"} {
		if _, err := ParsePrefix(in); err == nil {
			t.Errorf("ParsePrefix(%q) took it", in)
		}
	}
	hosts := Hosts(netip.MustParsePrefix("192.168.1.0/24"))
	if len(hosts) != 254 || hosts[0].String() != "192.168.1.1" || hosts[253].String() != "192.168.1.254" {
		t.Errorf("Hosts of a /24: %d, %v … %v", len(hosts), hosts[0], hosts[len(hosts)-1])
	}
	if b := Broadcast(netip.MustParsePrefix("10.1.0.0/22")); b.String() != "10.1.3.255" {
		t.Errorf("Broadcast of 10.1.0.0/22 = %v", b)
	}
	big := Interface{IP: netip.MustParseAddr("10.20.30.40"), Prefix: netip.MustParsePrefix("10.0.0.0/8")}
	if p := ScanPrefix(big); p.String() != "10.20.30.0/24" {
		t.Errorf("ScanPrefix of a /8 = %v", p)
	}
}

func TestNetBIOS(t *testing.T) {
	req := netbiosRequest()
	if len(req) != 50 || string(req[13:15]) != "CK" {
		t.Fatalf("request %x", req)
	}
	// A response naming DESKTOP-ABC (unique, workstation), WORKGROUP (a
	// group) and DESKTOP-ABC again with the server suffix.
	resp := append([]byte{0x4c, 0x53, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0}, req[12:46]...)
	resp = append(resp, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0x41, 3)
	name := func(n string, suffix byte, flags uint16) []byte {
		b := []byte(n)
		for len(b) < 15 {
			b = append(b, ' ')
		}
		return append(b, suffix, byte(flags>>8), byte(flags))
	}
	resp = append(resp, name("WORKGROUP", 0x00, 0x8400)...)
	resp = append(resp, name("DESKTOP-ABC", 0x20, 0x0400)...)
	resp = append(resp, name("DESKTOP-ABC", 0x00, 0x0400)...)
	if got := parseNetBIOS(resp); got != "DESKTOP-ABC" {
		t.Errorf("parseNetBIOS = %q", got)
	}
	if got := parseNetBIOS(resp[:20]); got != "" {
		t.Errorf("parseNetBIOS of a cut response = %q", got)
	}
}

func TestMDNS(t *testing.T) {
	ip := netip.MustParseAddr("192.168.3.16")
	q, err := mdnsQuery(ip)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(q); err != nil {
		t.Fatal(err)
	}
	qs, _ := p.AllQuestions()
	if len(qs) != 2 || qs[0].Name.String() != "16.3.168.192.in-addr.arpa." {
		t.Fatalf("questions %v", qs)
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	b.StartAnswers()
	rev := dnsmessage.MustNewName("16.3.168.192.in-addr.arpa.")
	b.PTRResource(dnsmessage.ResourceHeader{Name: rev, Class: dnsmessage.ClassINET}, dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("Adas-iPhone.local.")})
	b.StartAdditionals()
	b.TXTResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("Ada’s iPhone._device-info._tcp.local."), Class: dnsmessage.ClassINET}, dnsmessage.TXTResource{TXT: []string{"model=iPhone15,2", "osxvers=18"}})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	name, model := parseMDNS(msg, ip)
	if name != "Adas-iPhone" || model != "iPhone15,2" {
		t.Errorf("parseMDNS = %q, %q", name, model)
	}
}

func TestCleanHostname(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.20")
	for in, want := range map[string]string{
		"iPhone.lan.":           "iPhone",
		"nas.home":              "nas",
		"Adas-MacBook.local.":   "Adas-MacBook",
		"192-168-1-20.isp.net.": "",
		"host-192.168.1.20":     "",
	} {
		if got := cleanHostname(in, ip); got != want {
			t.Errorf("cleanHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    Device
		kind Kind
		os   string
	}{
		{"gateway", Device{IsGateway: true, Vendor: "Huawei Device"}, KindRouter, ""},
		{"iPhone by its model", Device{Model: "iPhone15,2", Vendor: ""}, KindPhone, "iOS"},
		{"Mac by its model", Device{Model: "Mac14,2"}, KindComputer, "macOS"},
		{"iPhone by its port", Device{Ports: []int{62078}}, KindPhone, "iOS"},
		{"Windows by RDP", Device{Ports: []int{135, 139, 445, 3389}, NetBIOSName: "DESKTOP-ABC"}, KindComputer, "Windows"},
		{"printer", Device{Ports: []int{80, 515, 631, 9100}, Vendor: "Huawei Device"}, KindPrinter, ""},
		{"camera", Device{Ports: []int{80, 554}, Vendor: "Hangzhou Hikvision Digital Technology"}, KindCamera, ""},
		{"NAS by name", Device{NetBIOSName: "DS920", Ports: []int{139, 445, 5000, 5001}}, KindNAS, "Linux"},
		{"TV by UPnP", Device{UPnPName: "客厅的小米电视", UPnPModel: "MiTV"}, KindTV, ""},
		{"air conditioner", Device{Vendor: "GD Midea Air-Conditioning Equipment"}, KindIoT, ""},
		{"Xiaomi smart home", Device{Vendor: "Beijing Xiaomi Mobile Software"}, KindIoT, ""},
		{"Tmall Genie", Device{Vendor: "Zhejiang Tmall Technology"}, KindSpeaker, ""},
		{"Android phone", Device{Vendor: "Guangdong Oppo Mobile Telecommunications"}, KindPhone, "Android"},
		{"phone with a private address", Device{MAC: "D6:FA:BB:10:20:03", RandomMAC: true}, KindPhone, ""},
		{"router by its page", Device{Ports: []int{80}, HTTPTitle: "TL-WDR5620 路由器管理"}, KindRouter, ""},
		{"nothing known", Device{}, KindUnknown, ""},
	} {
		d := tc.d
		Classify(&d)
		if d.Kind != tc.kind || d.OS != tc.os {
			t.Errorf("%s: %s %q, want %s %q", tc.name, d.Kind.Label(), d.OS, tc.kind.Label(), tc.os)
		}
	}
}

func TestFormatPorts(t *testing.T) {
	if got := FormatPorts([]int{22, 80, 12345}); got != "22 SSH, 80 HTTP, 12345" {
		t.Errorf("FormatPorts = %q", got)
	}
}

func TestNoPrefix(t *testing.T) {
	if hosts := Hosts(netip.Prefix{}); len(hosts) != 0 {
		t.Errorf("%d hosts in no prefix", len(hosts))
	}
	if b := Broadcast(netip.Prefix{}); b.IsValid() {
		t.Errorf("broadcast of no prefix: %v", b)
	}
}

func TestNetBIOSText(t *testing.T) {
	// "测试电脑" in GBK, and cut in the middle of its last character.
	gbk := []byte{0xb2, 0xe2, 0xca, 0xd4, 0xb5, 0xe7, 0xc4, 0xd4, ' ', ' '}
	if got := netbiosText(gbk); got != "测试电脑" {
		t.Errorf("netbiosText(GBK) = %q", got)
	}
	if got := netbiosText(gbk[:7]); got != "测试电" {
		t.Errorf("netbiosText(cut GBK) = %q", got)
	}
	if got := netbiosText([]byte("DESKTOP-ABC    ")); got != "DESKTOP-ABC" {
		t.Errorf("netbiosText(ASCII) = %q", got)
	}
}
