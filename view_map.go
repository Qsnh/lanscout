package main

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/egoist/mygo/ui"
	"github.com/Qsnh/lanscout/scan"
)

// addressMap shows every address of the network as a cell, colored by
// what uses it, to find the free ones at a glance.
func (a *app) addressMap(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Grow(1).MinWidth(0).Radius(10).Border(1, t.Border).Clip().Children(func() {
		ui.Row(c).Padding(10, 14).Gap(16).AlignItems(ui.Center).Wrap().BorderWidth(0, 0, 1, 0).BorderColor(t.Border).Children(func() {
			for _, s := range []addressState{stateOnline, stateGateway, stateSelf, stateRecent, stateFree} {
				bg, _, border := a.cellColors(t, s, scan.KindUnknown)
				ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
					ui.Box(c).Size(12, 12).Radius(3).Background(bg).Border(1, border)
					ui.Text(c, stateLabel(s)).FontSize(12)
				})
			}
			ui.Spacer(c)
			ui.Text(c, "点击空闲地址即可复制").FontSize(12).TextColor(t.TextMuted)
		})
		if !a.prefix.IsValid() {
			ui.Column(c).Grow(1).Center().Children(func() {
				ui.Text(c, "扫描后，这里会显示网段里每个地址的使用情况").TextColor(t.TextMuted)
			})
			return
		}
		ui.Scroll(c).Grow(1).Padding(14).Children(func() {
			ui.Grid(c).ColumnTracks(repeat(ui.Fr(1), 16)...).Gap(6).Children(func() {
				ip := a.prefix.Addr()
				for range 1 << (32 - a.prefix.Bits()) {
					a.addressCell(c, ip)
					ip = ip.Next()
				}
			})
		})
	})
}

func repeat(t ui.Track, n int) []ui.Track {
	out := make([]ui.Track, n)
	for i := range out {
		out[i] = t
	}
	return out
}

func stateLabel(s addressState) string {
	switch s {
	case stateOnline:
		return "在线"
	case stateGateway:
		return "网关"
	case stateSelf:
		return "本机"
	case stateRecent:
		return "近期使用"
	case stateReserved:
		return "保留地址"
	}
	return "空闲"
}

// cellColors returns the background, text and border colors of a cell.
func (a *app) cellColors(t *ui.Theme, s addressState, k scan.Kind) (bg, fg, border ui.Color) {
	switch s {
	case stateOnline:
		return t.Success.Alpha(0.16), t.Success, t.Success.Alpha(0.45)
	case stateGateway:
		color := kindColor(t, scan.KindRouter)
		return color.Alpha(0.3), color, color
	case stateSelf:
		return t.Accent, t.AccentText, t.Accent
	case stateRecent:
		return t.Warning.Alpha(0.12), t.Warning, t.Warning.Alpha(0.5)
	case stateReserved:
		return t.Surface, t.TextMuted.Alpha(0.6), t.Border
	}
	return t.Background, t.TextMuted, t.Border
}

func (a *app) addressCell(c *ui.Context, ip netip.Addr) {
	t := c.Theme()
	s := a.stateOf(ip)
	d, online := a.devices[ip]
	bg, fg, border := a.cellColors(t, s, d.Kind)

	b := ip.As4()
	label := strconv.Itoa(int(b[3]))
	if a.prefix.Bits() < 24 {
		label = fmt.Sprintf("%d.%d", b[2], b[3])
	}

	cell := ui.Column(c.Key(ip)).Height(48).Radius(8).Center().Gap(2).Background(bg).Border(1, border)
	switch s {
	case stateReserved:
		cell.Stripes(t.Border, 1, 5, 45)
	case stateRecent:
		cell.BorderStyle(ui.BorderDashed)
	}
	if s != stateReserved {
		cell.Cursor(ui.CursorPointer)
		if cell.Hovered() {
			cell.Border(1, fg)
		}
	}
	if ip == a.chosen {
		cell.Border(2, t.Accent)
	}
	cell.Tooltip(a.cellTip(ip, s, d))
	cell.Children(func() {
		ui.Text(c, label).FontSize(13).FontWeight(600).TextColor(fg)
		if online {
			ui.Icon(c, kindIcons[d.Kind]).FontSize(11).TextColor(fg)
		}
	})
	if cell.Clicked() {
		switch s {
		case stateFree:
			a.copy(c, ip.String())
		case stateReserved:
		default:
			a.chosen = ip
		}
	}
}

func (a *app) cellTip(ip netip.Addr, s addressState, d scan.Device) string {
	switch s {
	case stateFree:
		return ip.String() + " · 空闲，点击复制"
	case stateReserved:
		if ip == a.prefix.Addr() {
			return ip.String() + " · 网络地址，不能分配"
		}
		return ip.String() + " · 广播地址，不能分配"
	case stateRecent:
		r := a.seen()[ip]
		name := r.Name
		if name == "" {
			name = scan.Brand(r.Vendor)
		}
		return fmt.Sprintf("%s · 离线（%s 最后在线）%s", ip, r.LastSeen.Format("01-02 15:04"), prefixed(" · ", name))
	}
	name := d.Name()
	if name == "" {
		name = scan.Brand(d.Vendor)
	}
	return fmt.Sprintf("%s · %s%s", ip, d.Kind.Label(), prefixed(" · ", name))
}

func prefixed(p, s string) string {
	if s == "" {
		return ""
	}
	return p + s
}

// freeSpansCard lists the longest runs of free addresses, from which to
// hand out static addresses or a DHCP pool.
func (a *app) freeSpansCard(c *ui.Context) {
	t := c.Theme()
	spans := a.freeSpans()
	ui.Column(c).Padding(14).Gap(10).Radius(10).Background(t.Surface).Border(1, t.Border).Shrink(0).Children(func() {
		ui.Text(c, "可分配的连续空闲地址").FontSize(13).Bold()
		if len(spans) == 0 {
			ui.Text(c, "没有空闲地址").FontSize(12.5).TextColor(t.TextMuted)
			return
		}
		for i, s := range spans[:min(len(spans), 6)] {
			ui.Row(c.Key(s.first)).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Text(c, s.label()).FontSize(12.5).Grow(1).MinWidth(0).SingleLine()
				badge := strconv.Itoa(s.len()) + " 个"
				if i == 0 {
					tag(c, badge, t.Success)
				} else {
					ui.Text(c, badge).FontSize(11.5).TextColor(t.TextMuted)
				}
				ui.Button(c, "复制").OnClick(func() { a.copy(c, s.String()) }).Tooltip("复制这段地址，可填入路由器的 DHCP 地址池或静态分配表")
			})
		}
		if len(spans) > 6 {
			ui.Textf(c, "另有 %d 段较短的空闲地址", len(spans)-6).FontSize(11.5).TextColor(t.TextMuted)
		}
		ui.Text(c, "未响应的地址不一定空闲：关机、休眠或禁 ping 的设备不会显示。分配前建议对照路由器的 DHCP 列表。").FontSize(11.5).TextColor(t.TextMuted)
	})
}
