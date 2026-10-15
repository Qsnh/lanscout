package scan

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net"
	"strings"
	"sync"
)

// oui.txt.gz maps MAC prefixes to their vendors: lines of the prefix in
// hex (6, 7 or 9 digits, for the IEEE's MA-L, MA-M and MA-S blocks), a tab
// and the vendor. gen_oui.go makes it from Wireshark's manuf file.
//
//go:generate go run gen_oui.go manuf
//go:embed oui.txt.gz
var ouiData []byte

var (
	ouiOnce sync.Once
	ouiMap  map[string]string // by prefix in hex, upper case
)

func loadOUI() {
	ouiMap = make(map[string]string, 60000)
	zr, err := gzip.NewReader(bytes.NewReader(ouiData))
	if err != nil {
		return
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		prefix, name, ok := strings.Cut(sc.Text(), "\t")
		if ok {
			ouiMap[prefix] = name
		}
	}
}

// NormalizeMAC writes a MAC address as "AA:BB:CC:DD:EE:FF", from any of the
// forms systems print it in ("a:b:c:d:e:f" on macOS, "aa-bb-cc-dd-ee-ff" on
// Windows). It returns "" for what is not a unicast MAC address.
func NormalizeMAC(s string) string {
	s = strings.TrimSpace(s)
	sep := ":"
	if strings.Contains(s, "-") {
		sep = "-"
	}
	parts := strings.Split(s, sep)
	if len(parts) != 6 {
		return ""
	}
	var b strings.Builder
	var sum, ff int
	for i, p := range parts {
		if len(p) == 0 || len(p) > 2 {
			return ""
		}
		if len(p) == 1 {
			p = "0" + p
		}
		p = strings.ToUpper(p)
		for _, r := range p {
			if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'F') {
				return ""
			}
		}
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(p)
		if p != "00" {
			sum++
		}
		if p == "FF" {
			ff++
		}
	}
	out := b.String()
	if sum == 0 || ff == 6 {
		return "" // incomplete entries and broadcast
	}
	if hw, err := net.ParseMAC(out); err != nil || hw[0]&1 == 1 {
		return "" // multicast
	}
	return out
}

// IsRandomMAC reports whether mac is locally administered, as the private
// Wi-Fi addresses of iOS, Android and Windows are.
func IsRandomMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) > 0 && hw[0]&2 != 0
}

// Vendor returns the maker registered for mac, or "".
func Vendor(mac string) string {
	ouiOnce.Do(loadOUI)
	hex := strings.ReplaceAll(strings.ToUpper(mac), ":", "")
	if len(hex) != 12 {
		return ""
	}
	// The longest registered prefix wins: MA-S, then MA-M, then MA-L.
	for _, n := range []int{9, 7, 6} {
		if v, ok := ouiMap[hex[:n]]; ok {
			if v == "Private" {
				return ""
			}
			return v
		}
	}
	return ""
}

// brands gives the makers common in Chinese homes and offices their
// Chinese names, matched by a word of the registered name.
var brands = []struct{ match, name string }{
	{"apple", "苹果 Apple"},
	{"huawei", "华为 Huawei"},
	{"honor", "荣耀 Honor"},
	{"xiaomi", "小米 Xiaomi"},
	{"beijing xiaomi", "小米 Xiaomi"},
	{"redmi", "红米 Redmi"},
	{"oppo", "OPPO"},
	{"vivo", "vivo"},
	{"oneplus", "一加 OnePlus"},
	{"realme", "realme"},
	{"meizu", "魅族 Meizu"},
	{"samsung", "三星 Samsung"},
	{"lenovo", "联想 Lenovo"},
	{"motorola", "摩托罗拉 Motorola"},
	{"zte", "中兴 ZTE"},
	{"tp-link", "普联 TP-Link"},
	{"tplink", "普联 TP-Link"},
	{"mercury", "水星 Mercury"},
	{"tenda", "腾达 Tenda"},
	{"h3c", "新华三 H3C"},
	{"ruijie", "锐捷 Ruijie"},
	{"phicomm", "斐讯 Phicomm"},
	{"netgear", "网件 Netgear"},
	{"asustek", "华硕 ASUS"},
	{"asus", "华硕 ASUS"},
	{"cisco", "思科 Cisco"},
	{"fiberhome", "烽火 FiberHome"},
	{"hikvision", "海康威视 Hikvision"},
	{"ezviz", "萤石 EZVIZ"},
	{"dahua", "大华 Dahua"},
	{"uniview", "宇视 Uniview"},
	{"espressif", "乐鑫 Espressif (物联网模组)"},
	{"tuya", "涂鸦 Tuya (物联网)"},
	{"synology", "群晖 Synology"},
	{"qnap", "威联通 QNAP"},
	{"intel", "英特尔 Intel"},
	{"realtek", "瑞昱 Realtek"},
	{"dell", "戴尔 Dell"},
	{"hewlett", "惠普 HP"},
	{"hp inc", "惠普 HP"},
	{"microsoft", "微软 Microsoft"},
	{"sony", "索尼 Sony"},
	{"nintendo", "任天堂 Nintendo"},
	{"amazon", "亚马逊 Amazon"},
	{"google", "谷歌 Google"},
	{"tmall", "天猫精灵 Tmall Genie"},
	{"baidu", "百度 Baidu"},
	{"hisense", "海信 Hisense"},
	{"tcl", "TCL"},
	{"skyworth", "创维 Skyworth"},
	{"haier", "海尔 Haier"},
	{"midea", "美的 Midea"},
	{"gree", "格力 Gree"},
	{"brother", "兄弟 Brother"},
	{"canon", "佳能 Canon"},
	{"seiko epson", "爱普生 Epson"},
	{"epson", "爱普生 Epson"},
	{"ricoh", "理光 Ricoh"},
	{"kyocera", "京瓷 Kyocera"},
	{"fuji xerox", "富士施乐 Fuji Xerox"},
	{"xerox", "施乐 Xerox"},
	{"raspberry", "树莓派 Raspberry Pi"},
	{"hon hai", "鸿海 Foxconn"},
	{"azurewave", "海华 AzureWave (无线网卡)"},
	{"liteon", "光宝 Lite-On (无线网卡)"},
	{"chongqing fugui", "富桂 (无线网卡)"},
	{"murata", "村田 Murata (无线模组)"},
	{"amlogic", "晶晨 Amlogic"},
	{"rockchip", "瑞芯微 Rockchip"},
	{"allwinner", "全志 Allwinner"},
	{"china mobile", "中国移动"},
	{"china unicom", "中国联通"},
	{"china telecom", "中国电信"},
	{"ubiquiti", "Ubiquiti"},
	{"mikrotik", "MikroTik"},
	{"vmware", "VMware 虚拟机"},
	{"parallels", "Parallels 虚拟机"},
	{"oracle", "VirtualBox 虚拟机"},
}

// Brand returns how to show vendor: its Chinese name and brand for the
// makers in brands, else vendor itself.
func Brand(vendor string) string {
	if vendor == "" {
		return ""
	}
	lower := strings.ToLower(vendor)
	for _, b := range brands {
		if i := strings.Index(lower, b.match); i >= 0 {
			// A word, not part of one: "intel" in "Intellicheck" is not Intel.
			end := i + len(b.match)
			if (i == 0 || !isLetter(lower[i-1])) && (end == len(lower) || !isLetter(lower[end])) {
				return b.name
			}
		}
	}
	return vendor
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' }
