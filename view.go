package main

import (
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/Qsnh/lanscout/scan"
)

const (
	pageTable = iota
	pageMap
)

func (a *app) view(c *ui.Context) {
	t := c.Theme()
	if a.toast != "" {
		c.Toast(a.toast)
		a.toast = ""
	}
	ui.Column(c).Fill().Background(t.Background).Children(func() {
		a.header(c)
		a.statusLine(c)
		a.stats(c)
		a.toolbar(c)
		ui.Row(c).Grow(1).MinHeight(0).AlignItems(ui.Stretch).Gap(12).Padding(0, 16, 16).Children(func() {
			if a.page == pageMap {
				a.addressMap(c)
				ui.Column(c).Width(330).Shrink(0).Gap(12).Children(func() {
					a.freeSpansCard(c)
					a.details(c).Grow(1)
				})
			} else {
				a.deviceTable(c)
				a.details(c).Width(330).Shrink(0)
			}
		})
	})
	if c.Shortcut(ui.Cmd, ui.KeyR) {
		a.startScan()
	}
}

// header holds the app's name and what to scan: the interface, the
// network, and the button that starts or stops the scan.
func (a *app) header(c *ui.Context) {
	t := c.Theme()
	ui.Row(c).Padding(14, 16).Gap(12).AlignItems(ui.Center).BorderWidth(0, 0, 1, 0).BorderColor(t.Border).Children(func() {
		ui.Box(c).Size(36, 36).Radius(10).Background(t.Accent).Center().Children(func() {
			ui.Icon(c, iconRadar).FontSize(20).TextColor(t.AccentText)
		})
		ui.Column(c).Gap(2).Children(func() {
			ui.Text(c, "LanScout").FontSize(17).Bold()
			ui.Text(c, "局域网设备与 IP 扫描").FontSize(12).TextColor(t.TextMuted)
		})
		ui.Spacer(c)
		if a.ifaceErr != "" {
			ui.Text(c, a.ifaceErr).TextColor(t.Danger)
			ui.PrimaryButton(c, "重新检测").OnClick(a.startScan)
			return
		}
		ui.Text(c, "网卡").FontSize(12).TextColor(t.TextMuted)
		label := a.ifaceLabel
		ui.Select(c, &label, a.interfaceLabels()).Label("网卡").Width(320).Disabled(a.scanning)
		if label != a.ifaceLabel {
			a.chooseInterface(label)
		}
		ui.Text(c, "网段").FontSize(12).TextColor(t.TextMuted)
		ui.TextInput(c, &a.network).Label("网段").Placeholder("192.168.1.0/24").Width(170).Disabled(a.scanning).OnSubmit(a.startScan)
		if a.scanning {
			ui.Button(c, "停止扫描").Width(96).OnClick(a.stopScan)
		} else {
			ui.PrimaryButton(c, "开始扫描").Width(96).OnClick(a.startScan)
		}
	})
}

// statusLine shows the scan's progress, or how the last one went.
func (a *app) statusLine(c *ui.Context) {
	t := c.Theme()
	ui.Row(c).Height(40).PaddingX(16).Gap(12).AlignItems(ui.Center).Children(func() {
		switch {
		case a.networkErr != "":
			ui.Text(c, a.networkErr).FontSize(12).TextColor(t.Danger)
		case a.scanning:
			ui.Spinner(c).Label("正在扫描")
			p := a.progress
			ui.Textf(c, "%s  %d / %d", p.Phase, p.Done, p.Total).FontSize(12).TextColor(t.TextMuted).Width(170)
			ui.Progress(c, p.Fraction).Grow(1)
			ui.Textf(c, "%.0f%%", p.Fraction*100).FontSize(12).TextColor(t.TextMuted).Width(40).TextAlign(ui.End)
		case a.took > 0:
			ui.Textf(c, "扫描完成：%s 共 %d 个地址，发现 %d 台在线设备，用时 %.1f 秒（%s）", a.prefix, len(scan.Hosts(a.prefix)), len(a.devices), a.took.Seconds(), a.started.Format("15:04:05")).
				FontSize(12).TextColor(t.TextMuted).Grow(1).SingleLine()
			ui.Text(c, shortcutHint()).FontSize(12).TextColor(t.TextMuted)
		default:
			ui.Text(c, "选择网卡和网段，然后点击「开始扫描」").FontSize(12).TextColor(t.TextMuted)
		}
	})
	if !a.scanning && a.took > 0 && len(a.devices) <= 1 {
		a.permissionHint(c)
	}
}

func shortcutHint() string {
	if runtime.GOOS == "darwin" {
		return "⌘R 重新扫描"
	}
	return "Ctrl+R 重新扫描"
}

// permissionHint explains a scan that found nothing but this computer,
// which is what the system's privacy settings or a firewall cause.
func (a *app) permissionHint(c *ui.Context) {
	t := c.Theme()
	msg := "只发现了本机。请确认电脑已连接到局域网，并且防火墙没有阻止 LanScout 访问网络。"
	if runtime.GOOS == "darwin" {
		msg = "只发现了本机。macOS 需要授权才能访问局域网：请到「系统设置 › 隐私与安全性 › 本地网络」中打开 LanScout，然后重新扫描。"
	}
	ui.Row(c).Margin(0, 16, 10).Padding(10, 14).Gap(10).Radius(8).AlignItems(ui.Center).
		Background(t.Warning.Alpha(0.12)).Border(1, t.Warning.Alpha(0.4)).Children(func() {
		ui.Icon(c, iconInfo).TextColor(t.Warning)
		ui.Text(c, msg).FontSize(12.5).Grow(1)
	})
}

// stats sums the network up in tiles.
func (a *app) stats(c *ui.Context) {
	t := c.Theme()
	online, free, recent := a.counts()
	var random int
	for _, d := range a.devices {
		if d.RandomMAC {
			random++
		}
	}
	gw, self := a.iface.Gateway, a.iface.IP
	gwName := "—"
	if d, ok := a.devices[gw]; ok && d.Name() != "" {
		gwName = d.Name()
	}
	ui.Grid(c).Columns(5).Gap(12).Padding(0, 16, 12).Children(func() {
		tile(c, "在线设备", strconv.Itoa(online), fmt.Sprintf("其中 %d 台使用随机 MAC", random), t.Success)
		tile(c, "空闲 IP", strconv.Itoa(free), fmt.Sprintf("可用地址共 %d 个", len(scan.Hosts(a.prefix))), t.Accent)
		tile(c, "近期使用", strconv.Itoa(recent), "30 天内出现过，现在离线", t.Warning)
		tile(c, "网关", addrText(gw), gwName, kindColor(t, scan.KindRouter))
		tile(c, "本机", addrText(self), ifaceName(a.iface), kindColor(t, scan.KindComputer))
	})
}

func ifaceName(i scan.Interface) string {
	if i.Label != "" && i.Label != i.Name {
		return i.Label + " (" + i.Name + ")"
	}
	return i.Name
}

func addrText(ip netip.Addr) string {
	if !ip.IsValid() {
		return "—"
	}
	return ip.String()
}

func tile(c *ui.Context, title, value, note string, accent ui.Color) {
	t := c.Theme()
	ui.Column(c).Padding(12, 14).Gap(4).Radius(10).Background(t.Surface).Border(1, t.Border).MinWidth(0).Children(func() {
		ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
			ui.Box(c).Size(8, 8).Radius(4).Background(accent)
			ui.Text(c, title).FontSize(12).TextColor(t.TextMuted)
		})
		ui.Text(c, value).FontSize(22).Bold().SingleLine()
		ui.Text(c, note).FontSize(11.5).TextColor(t.TextMuted).SingleLine()
	})
}

// toolbar switches between the table and the map, and searches.
func (a *app) toolbar(c *ui.Context) {
	ui.Row(c).Padding(0, 16, 10).Gap(12).AlignItems(ui.Center).Children(func() {
		ui.Segmented(c, &a.page, "设备列表", "IP 分布图").Label("视图")
		ui.SearchField(c, &a.query).Label("搜索 IP、名称、厂商、MAC、端口").Width(300)
		ui.Checkbox(c, &a.showOffline, "显示离线设备")
		ui.Spacer(c)
		ui.MenuButton(c, "更多", func(m *ui.Menu) {
			if m.Item("导出为 CSV 表格…").Chosen() {
				a.export()
			}
			if m.Item("复制在线设备列表").Chosen() {
				c.WriteClipboard(a.summary())
				c.Toast("已复制在线设备列表")
			}
			m.Separator()
			if m.Item("清除本网段的历史记录").Chosen() {
				a.forget()
				c.Toast("已清除历史记录")
			}
		})
	})
}

// summary writes the devices online as lines of text, for the clipboard.
func (a *app) summary() string {
	var b strings.Builder
	for _, e := range a.entries() {
		if e.Offline {
			continue
		}
		name := e.Name()
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\n", e.IP, e.MAC, name, e.Kind.Label(), scan.Brand(e.Vendor))
	}
	return b.String()
}

// deviceTable lists the devices, in columns the user sorts.
func (a *app) deviceTable(c *ui.Context) {
	t := c.Theme()
	rows := a.entries()
	a.row = -1
	for i, e := range rows {
		if e.IP == a.chosen {
			a.row = i
		}
	}
	cols := []ui.TableColumn{
		{Title: "IP 地址", ID: colIP, Width: 166, MinWidth: 120, Sortable: true},
		{Title: "设备名称", ID: colName, MinWidth: 120, Sortable: true},
		{Title: "类型", ID: colKind, Width: 108, Sortable: true},
		{Title: "厂商", ID: colVendor, Width: 130, Sortable: true},
		{Title: "MAC 地址", ID: colMAC, Width: 160, Sortable: true},
		{Title: "开放端口", ID: colPorts, Width: 100, Sortable: true},
		{Title: "延迟", ID: colRTT, Width: 70, Align: ui.End, Sortable: true},
	}
	a.table.Selected = &a.row
	a.table.Sort = &a.sort
	a.table.Key = func(i int) any { return rows[i].IP }
	a.table.Label = func(i int) string { return rows[i].IP.String() }
	ui.Column(c).Grow(1).MinWidth(0).Radius(10).Border(1, t.Border).Clip().Children(func() {
		if len(rows) == 0 {
			a.emptyTable(c)
			return
		}
		ui.Table(c, &a.table, cols, len(rows), func(row, col int) {
			a.cell(c, rows[row], col)
		}).Grow(1).Label("设备列表")
	})
	if a.row >= 0 && a.row < len(rows) {
		a.chosen = rows[a.row].IP
	}
}

func (a *app) emptyTable(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Grow(1).Center().Gap(10).Children(func() {
		switch {
		case a.scanning:
			ui.Spinner(c).Label("正在扫描")
			ui.Text(c, "正在扫描局域网，发现的设备会显示在这里").TextColor(t.TextMuted)
		case a.query != "":
			ui.Textf(c, "没有与「%s」匹配的设备", a.query).TextColor(t.TextMuted)
		default:
			ui.Icon(c, iconRadar).FontSize(36).TextColor(t.TextMuted)
			ui.Text(c, "还没有扫描结果").TextColor(t.TextMuted)
		}
	})
}

func (a *app) cell(c *ui.Context, e entry, col int) {
	t := c.Theme()
	d := e.Device
	// On the chosen row, in the accent color, text takes the row's color.
	muted, kind := t.TextMuted, kindColor(t, d.Kind)
	if d.IP == a.chosen {
		muted, kind = t.AccentText.Alpha(0.75), t.AccentText
	}
	el := ui.Row(c).Gap(6).AlignItems(ui.Center).MinWidth(0)
	if e.Offline {
		el.Opacity(0.55)
	}
	el.ContextMenu(func(m *ui.Menu) { a.deviceMenu(c, m, d) })
	el.Children(func() {
		switch col {
		case 0:
			ui.Text(c, d.IP.String()).Font("monospace").SingleLine()
			switch {
			case d.IsGateway:
				tag(c, "网关", kindColor(t, scan.KindRouter))
			case d.IsSelf:
				tag(c, "本机", t.Accent)
			case e.Offline:
				tag(c, "离线", t.TextMuted)
			}
		case 1:
			if name := d.Name(); name != "" {
				ui.Text(c, name).SingleLine()
			} else {
				ui.Text(c, "—").TextColor(muted)
			}
		case 2:
			ui.Icon(c, kindIcons[d.Kind]).TextColor(kind)
			ui.Text(c, d.Kind.Label()).SingleLine()
		case 3:
			switch {
			case d.Vendor != "":
				ui.Text(c, scan.Brand(d.Vendor)).SingleLine().Tooltip(d.Vendor)
			case d.RandomMAC:
				ui.Text(c, "随机 MAC").TextColor(muted).Tooltip("设备开启了私有 Wi-Fi 地址（多为手机），无法从 MAC 识别厂商")
			default:
				ui.Text(c, "—").TextColor(muted)
			}
		case 4:
			if d.MAC != "" {
				ui.Text(c, d.MAC).Font("monospace").FontSize(12).SingleLine()
			} else {
				ui.Text(c, "—").TextColor(muted)
			}
		case 5:
			if len(d.Ports) == 0 {
				ui.Text(c, "—").TextColor(muted)
				return
			}
			nums := make([]string, len(d.Ports))
			for i, p := range d.Ports {
				nums[i] = strconv.Itoa(p)
			}
			ui.Text(c, strings.Join(nums, ", ")).FontSize(12).SingleLine().Tooltip(scan.FormatPorts(d.Ports))
		case 6:
			ui.Spacer(c)
			ui.Text(c, rttText(d.RTT)).FontSize(12).TextColor(muted)
		}
	})
}

func rttText(d time.Duration) string {
	switch {
	case d <= 0:
		return "—"
	case d < time.Millisecond:
		return "<1 ms"
	}
	return fmt.Sprintf("%d ms", d.Milliseconds())
}

// tag is a short label in a pill of its color.
func tag(c *ui.Context, text string, color ui.Color) {
	ui.Box(c).Padding(1, 6).Radius(5).Background(color.Alpha(0.15)).Shrink(0).Children(func() {
		ui.Text(c, text).FontSize(10.5).FontWeight(600).TextColor(color)
	})
}

func (a *app) deviceMenu(c *ui.Context, m *ui.Menu, d scan.Device) {
	if m.Item("复制 IP 地址").Chosen() {
		a.copy(c, d.IP.String())
	}
	if d.MAC != "" && m.Item("复制 MAC 地址").Chosen() {
		a.copy(c, d.MAC)
	}
	if name := d.Name(); name != "" && m.Item("复制设备名称").Chosen() {
		a.copy(c, name)
	}
	if u := webURL(d); u != "" {
		m.Separator()
		if m.Item("在浏览器中打开").Chosen() {
			c.OpenURL(u)
		}
	}
}

func (a *app) copy(c *ui.Context, s string) {
	c.WriteClipboard(s)
	c.Toast("已复制 " + s)
}

// webURL returns the address of the device's web page, "" for none.
func webURL(d scan.Device) string {
	for _, p := range []struct {
		port   int
		scheme string
	}{{80, "http"}, {443, "https"}, {8080, "http"}, {8443, "https"}, {5000, "http"}} {
		if d.HasPort(p.port) {
			host := d.IP.String()
			if p.port != 80 && p.port != 443 {
				host += ":" + strconv.Itoa(p.port)
			}
			return p.scheme + "://" + host
		}
	}
	return ""
}

// details shows everything known of the device chosen.
func (a *app) details(c *ui.Context) ui.Element {
	t := c.Theme()
	d, ok := a.devices[a.chosen]
	offline := false
	var lastSeen time.Time
	if ok {
		lastSeen = d.SeenAt
	} else if r, seen := a.seen()[a.chosen]; seen && a.chosen.IsValid() {
		d = scan.Device{IP: a.chosen, MAC: r.MAC, Vendor: r.Vendor, MDNSName: r.Name, Kind: r.Kind, RandomMAC: scan.IsRandomMAC(r.MAC)}
		ok, offline, lastSeen = true, true, r.LastSeen
	}
	panel := ui.Column(c).MinHeight(0).Radius(10).Background(t.Surface).Border(1, t.Border).Clip()
	return panel.Children(func() {
		if !ok {
			ui.Column(c).Grow(1).Center().Gap(10).Padding(24).Children(func() {
				ui.Icon(c, iconInfo).FontSize(30).TextColor(t.TextMuted)
				ui.Text(c, "选择一台设备，查看它的详细信息").TextColor(t.TextMuted).TextAlign(ui.Center)
			})
			return
		}
		ui.Scroll(c).Grow(1).Padding(16).Gap(16).Selectable().Children(func() {
			color := kindColor(t, d.Kind)
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				ui.Box(c).Size(46, 46).Radius(12).Background(color.Alpha(0.15)).Center().Shrink(0).Children(func() {
					ui.Icon(c, kindIcons[d.Kind]).FontSize(24).TextColor(color)
				})
				ui.Column(c).Gap(3).MinWidth(0).Grow(1).Children(func() {
					title := d.Name()
					if title == "" {
						title = d.IP.String()
					}
					ui.Text(c, title).FontSize(16).Bold().MaxLines(2)
					sub := d.Kind.Label()
					if d.OS != "" {
						sub += " · " + d.OS
					}
					if offline {
						sub += " · 离线"
					}
					ui.Text(c, sub).FontSize(12).TextColor(t.TextMuted)
				})
			})
			ui.Row(c).Gap(8).Wrap().Children(func() {
				ui.Button(c, "复制 IP").OnClick(func() { a.copy(c, d.IP.String()) })
				if d.MAC != "" {
					ui.Button(c, "复制 MAC").OnClick(func() { a.copy(c, d.MAC) })
				}
				if u := webURL(d); u != "" && !offline {
					ui.Button(c, "打开网页").OnClick(func() { c.OpenURL(u) })
				}
			})

			section(c, "网络", func() {
				field(c, "IP 地址", d.IP.String())
				mac := d.MAC
				if d.RandomMAC {
					mac += "（随机）"
				}
				field(c, "MAC 地址", mac)
				vendor := scan.Brand(d.Vendor)
				if vendor != d.Vendor && d.Vendor != "" {
					vendor += "\n" + d.Vendor
				}
				field(c, "厂商", vendor)
				if !offline {
					field(c, "延迟", rttText(d.RTT))
					field(c, "发现方式", strings.Join(d.Via, "、"))
				}
				if !lastSeen.IsZero() {
					field(c, "最后在线", lastSeen.Format("2006-01-02 15:04:05"))
				}
			})
			if d.DNSName != "" || d.MDNSName != "" || d.NetBIOSName != "" || d.UPnPName != "" || d.Model != "" || d.HTTPTitle != "" {
				section(c, "名称与型号", func() {
					field(c, "mDNS", d.MDNSName)
					field(c, "NetBIOS", d.NetBIOSName)
					field(c, "DNS", d.DNSName)
					field(c, "UPnP", d.UPnPName)
					model := d.Model
					if d.UPnPModel != "" {
						model = strings.TrimSpace(d.UPnPMaker + " " + d.UPnPModel)
					}
					field(c, "型号", model)
					field(c, "网页标题", d.HTTPTitle)
					field(c, "Web 服务", d.HTTPServer)
				})
			}
			if !offline {
				section(c, "开放端口", func() {
					if len(d.Ports) == 0 {
						ui.Text(c, "未发现常见的开放端口").FontSize(12.5).TextColor(t.TextMuted)
					}
					for _, p := range d.Ports {
						ui.Row(c).Gap(10).Children(func() {
							ui.Text(c, strconv.Itoa(p)).Font("monospace").FontSize(12.5).Width(52)
							ui.Text(c, scan.PortName(p)).FontSize(12.5).TextColor(t.TextMuted)
						})
					}
				})
			}
			if !offline && len(d.Via) == 1 && d.Via[0] == "ARP" {
				note(c, "这台设备只出现在系统的 ARP 表里，没有回应 ping 和端口探测：可能在休眠（手机常见），也可能刚离开网络，系统会把它的记录保留一段时间（macOS 最长约 20 分钟）。")
			}
			if d.RandomMAC {
				note(c, "这台设备开启了「私有 Wi-Fi 地址」，每个网络用不同的随机 MAC，所以无法识别厂商。若要在路由器里为它绑定固定 IP，请先在设备的 Wi-Fi 设置中为本网络关闭私有地址。")
			}
			if offline {
				note(c, "这台设备现在没有响应，但最近在这个地址出现过。分配 IP 时建议避开这个地址，以免设备开机后冲突。")
			}
		})
	})
}

func section(c *ui.Context, title string, body func()) {
	t := c.Theme()
	ui.Column(c).Gap(8).Children(func() {
		ui.Text(c, title).FontSize(12).FontWeight(600).TextColor(t.TextMuted)
		body()
	})
}

func field(c *ui.Context, label, value string) {
	if value == "" {
		return
	}
	t := c.Theme()
	ui.Row(c).Gap(10).AlignItems(ui.Start).Children(func() {
		ui.Text(c, label).FontSize(12.5).TextColor(t.TextMuted).Width(64).Shrink(0)
		ui.Text(c, value).FontSize(12.5).Grow(1).MinWidth(0)
	})
}

func note(c *ui.Context, text string) {
	t := c.Theme()
	ui.Row(c).Gap(8).Padding(10, 12).Radius(8).AlignItems(ui.Start).Background(t.Accent.Alpha(0.08)).Children(func() {
		ui.Icon(c, iconInfo).TextColor(t.Accent).Shrink(0)
		ui.Text(c, text).FontSize(12).Grow(1).MinWidth(0)
	})
}
