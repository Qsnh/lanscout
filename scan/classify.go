package scan

import (
	"regexp"
	"strings"
)

// Classify works out what d is, and which system it runs, from everything
// known of it. The clues are weighed from the most telling (what the device
// says it is) to the least (who made its network card).
func Classify(d *Device) {
	d.Kind, d.OS = classify(d)
}

type rule struct {
	pattern *regexp.Regexp
	kind    Kind
	os      string
}

func rules(kind Kind, os string, words ...string) rule {
	return rule{regexp.MustCompile(`(?i)` + strings.Join(words, "|")), kind, os}
}

// modelRules match the hardware models of Apple's mDNS device info.
var modelRules = []rule{
	rules(KindPhone, "iOS", `^iphone`),
	rules(KindTablet, "iPadOS", `^ipad`),
	rules(KindComputer, "macOS", `^(macbook|imac|macmini|macpro|mac\d|virtualmac)`),
	rules(KindTV, "tvOS", `^appletv`),
	rules(KindSpeaker, "", `^audioaccessory`),
}

// nameRules match the names devices give themselves, or their UPnP
// descriptions and web pages.
var nameRules = []rule{
	rules(KindPhone, "iOS", `iphone`),
	rules(KindTablet, "iPadOS", `ipad`),
	rules(KindComputer, "macOS", `macbook`, `\bimac\b`, `mac-?mini`, `mac-?studio`, `mac-?pro\b`, `\bmbp\b`),
	rules(KindTablet, "Android", `matepad`, `xiaomipad`, `mi-?pad`, `galaxy-?tab`, `honorpad`),
	rules(KindPrinter, "", `printer`, `laserjet`, `officejet`, `deskjet`, `envy`, `^brn`, `^npi`, `epson`, `canon`, `mfc-?\d`, `打印`),
	rules(KindNAS, "Linux", `\bnas\b`, `diskstation`, `^ds\d{3}`, `synology`, `qnap`, `truenas`, `unraid`, `群晖`),
	rules(KindCamera, "", `camera`, `\bipc\b`, `\bnvr\b`, `hikvision`, `ezviz`, `dahua`, `imou`, `chuangmi`, `监控`, `摄像`),
	rules(KindTV, "", `\btv\b`, `-tv`, `tv-`, `appletv`, `chromecast`, `roku`, `firetv`, `mibox`, `mitv`, `bravia`, `shield`, `电视`, `盒子`),
	rules(KindSpeaker, "", `homepod`, `\becho\b`, `xiaoai`, `tmall`, `sonos`, `speaker`, `音箱`),
	rules(KindConsole, "", `\bps[45]\b`, `playstation`, `xbox`, `nintendo`),
	rules(KindIoT, "", `^esp[_-]`, `esp32`, `esp8266`, `tuya`, `yeelight`, `lumi-`, `aqara`, `zigbee`, `broadlink`, `miio`, `plug`, `bulb`, `smart-?home`),
	rules(KindRouter, "", `router`, `openwrt`, `luci`, `\bmesh\b`, `gateway`, `路由`, `网关`, `光猫`),
	rules(KindPhone, "Android", `android`, `galaxy`, `redmi`, `xiaomi`, `huawei`, `honor`, `\boppo`, `\bvivo`, `oneplus`, `realme`, `meizu`, `pixel`, `harmony`),
	rules(KindComputer, "Windows", `^desktop-`, `^laptop-`, `^win-`, `windows`),
	rules(KindServer, "Linux", `raspberrypi`, `ubuntu`, `debian`, `centos`, `fedora`, `proxmox`, `\bpve\b`, `server`),
}

// vendorRules match the maker of the network card.
var vendorRules = []rule{
	rules(KindPrinter, "", `brother`, `seiko epson`, `canon`, `kyocera`, `ricoh`, `xerox`, `lexmark`, `konica`, `pantum`),
	rules(KindCamera, "", `hikvision`, `dahua`, `ezviz`, `uniview`, `imou`, `axis comm`, `hanwha`),
	rules(KindNAS, "Linux", `synology`, `qnap`, `asustor`, `terramaster`),
	rules(KindTV, "", `hisense`, `skyworth`, `\btcl\b`, `roku`, `amlogic`),
	rules(KindSpeaker, "", `tmall`, `sonos`, `bose`, `baidu`),
	rules(KindIoT, "", `espressif`, `tuya`, `lumi united`, `broadlink`, `yeelink`, `chuangmi`, `gaoshengda`, `beken`, `silicon lab`, `texas instruments`, `shenzhen bilian`, `mxchip`, `philips lighting`, `signify`,
		`beijing xiaomi mobile`, `midea`, `gree electric`, `haier`, `\baux\b`, `ecovacs`, `roborock`, `dreame`, `opple`, `bull group`, `leedarson`, `aqara`),
	rules(KindConsole, "", `nintendo`, `sony interactive`),
	rules(KindServer, "Linux", `raspberry`),
	rules(KindComputer, "", `vmware`, `parallels`, `oracle`, `intel`, `realtek`, `azurewave`, `liteon`, `hon hai`, `dell`, `lenovo`, `hewlett`, `hp inc`, `asustek`, `micro-star`, `giga-byte`, `gigabyte`, `asrock`, `chongqing fugui`, `microsoft`, `quanta`, `compal`, `wistron`),
	rules(KindPhone, "Android", `oppo`, `vivo mobile`, `oneplus`, `realme`, `meizu`, `huawei device`, `honor device`, `xiaomi comm`, `samsung`, `motorola mobility`, `google`, `transsion`, `nubia`),
	rules(KindRouter, "", `tp-?link`, `mercury`, `tenda`, `h3c`, `ruijie`, `phicomm`, `netgear`, `ubiquiti`, `mikrotik`, `\bzte\b`, `fiberhome`, `huawei tech`, `cisco`, `juniper`, `aruba`, `d-link`, `linksys`, `eero`, `sagemcom`, `youhua`, `china mobile`),
}

func match(rs []rule, texts ...string) (Kind, string, bool) {
	for _, r := range rs {
		for _, t := range texts {
			if t != "" && r.pattern.MatchString(t) {
				return r.kind, r.os, true
			}
		}
	}
	return KindUnknown, "", false
}

func classify(d *Device) (Kind, string) {
	os := guessOS(d)
	pick := func(k Kind, o string) (Kind, string) {
		if o == "" {
			o = os
		}
		return k, o
	}
	switch {
	case d.IsGateway:
		return pick(KindRouter, "")
	case d.IsSelf:
		return pick(KindComputer, "")
	}
	if k, o, ok := match(modelRules, d.Model); ok {
		return pick(k, o)
	}
	names := []string{d.MDNSName, d.NetBIOSName, d.DNSName, d.UPnPName, d.UPnPModel, d.UPnPMaker}
	if k, o, ok := match(nameRules, names...); ok {
		return pick(k, o)
	}

	// The services a device offers.
	switch {
	case d.HasPort(9100) || d.HasPort(631) || d.HasPort(515):
		return pick(KindPrinter, "")
	case d.HasPort(62078):
		return pick(KindPhone, "iOS")
	case d.HasPort(3389) || d.HasPort(135):
		return pick(KindComputer, "Windows")
	case d.HasPort(554) && !d.HasPort(445):
		return pick(KindCamera, "")
	case d.HasPort(8008) || d.HasPort(8009):
		return pick(KindTV, "Android")
	case d.HasPort(548) || isApple(d) && (d.HasPort(445) || d.HasPort(22) || d.HasPort(5900) || d.HasPort(7000)):
		return pick(KindComputer, "macOS")
	case d.HasPort(5000) && d.HasPort(5001):
		return pick(KindNAS, "Linux")
	case d.HasPort(445) && d.HasPort(139):
		return pick(KindComputer, "Windows")
	}

	// What its web page says.
	if k, o, ok := match(nameRules, d.HTTPTitle, d.HTTPServer); ok {
		return pick(k, o)
	}
	if d.HasPort(53) && (d.HasPort(80) || d.HasPort(443)) {
		return pick(KindRouter, "")
	}
	if d.NetBIOSName != "" && !isApple(d) {
		return pick(KindComputer, "Windows")
	}

	// Who made its network card.
	if k, o, ok := match(vendorRules, d.Vendor); ok {
		// Phone makers' cards in a host offering services are more
		// likely in a box or a TV than in a phone.
		if k == KindPhone && len(d.Ports) > 0 {
			return pick(KindUnknown, "")
		}
		return pick(k, o)
	}
	if isApple(d) {
		if len(d.Ports) == 0 {
			return pick(KindPhone, "iOS")
		}
		return pick(KindComputer, "macOS")
	}
	if d.HasPort(22) && len(d.Ports) <= 3 {
		return pick(KindServer, "Linux")
	}
	// A private address with nothing else to go on is most likely a phone:
	// iOS and Android pick one for each Wi-Fi network.
	if d.RandomMAC && len(d.Ports) == 0 {
		return pick(KindPhone, "")
	}
	return pick(KindUnknown, "")
}

func isApple(d *Device) bool {
	return strings.HasPrefix(strings.ToLower(d.Vendor), "apple")
}

// guessOS reads the system from the clues that name it outright.
func guessOS(d *Device) string {
	server := strings.ToLower(d.HTTPServer)
	switch {
	case d.HasPort(3389) || d.HasPort(135) || d.NetBIOSName != "" && d.HasPort(445) && !isApple(d):
		return "Windows"
	case strings.HasPrefix(strings.ToLower(d.Model), "mac"):
		return "macOS"
	case strings.Contains(strings.ToLower(d.DNSName+d.MDNSName), "android"):
		return "Android"
	case strings.Contains(server, "linux") || strings.Contains(server, "openwrt"):
		return "Linux"
	}
	return ""
}
