package main

import (
	"github.com/egoist/mygo/ui"
	"github.com/Qsnh/lanscout/scan"
)

// The icons are Lucide's (lucide.dev, ISC license), drawn in the color of
// the text around them.
func icon(paths string) *ui.SVG {
	return ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">` + paths + `</svg>`))
}

var (
	iconRadar    = icon(`<path d="M19.07 4.93A10 10 0 0 0 6.99 3.34"/><path d="M4 6h.01"/><path d="M2.29 9.62A10 10 0 1 0 21.31 8.35"/><path d="M16.24 7.76A6 6 0 1 0 8.23 16.67"/><path d="M12 18h.01"/><path d="M17.99 11.66A6 6 0 0 1 15.77 16.67"/><circle cx="12" cy="12" r="2"/><path d="m13.41 10.59 5.66-5.66"/>`)
	iconCopy     = icon(`<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>`)
	iconExternal = icon(`<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h3"/>`)
	iconInfo     = icon(`<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>`)

	kindIcons = map[scan.Kind]*ui.SVG{
		scan.KindUnknown:  icon(`<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>`),
		scan.KindRouter:   icon(`<rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6.01 18H6"/><path d="M10.01 18H10"/><path d="M15 10v4"/><path d="M17.84 7.17a4 4 0 0 0-5.66 0"/><path d="M20.66 4.34a8 8 0 0 0-11.31 0"/>`),
		scan.KindComputer: icon(`<rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>`),
		scan.KindPhone:    icon(`<rect width="14" height="20" x="5" y="2" rx="2" ry="2"/><path d="M12 18h.01"/>`),
		scan.KindTablet:   icon(`<rect width="16" height="20" x="4" y="2" rx="2" ry="2"/><line x1="12" x2="12.01" y1="18" y2="18"/>`),
		scan.KindPrinter:  icon(`<polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect width="12" height="8" x="6" y="14"/>`),
		scan.KindCamera:   icon(`<path d="m22 8-6 4 6 4V8Z"/><rect width="14" height="12" x="2" y="6" rx="2" ry="2"/>`),
		scan.KindTV:       icon(`<rect width="20" height="15" x="2" y="7" rx="2" ry="2"/><polyline points="17 2 12 7 7 2"/>`),
		scan.KindNAS:      icon(`<line x1="22" x2="2" y1="12" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" x2="6.01" y1="16" y2="16"/><line x1="10" x2="10.01" y1="16" y2="16"/>`),
		scan.KindSpeaker:  icon(`<rect width="16" height="20" x="4" y="2" rx="2"/><path d="M12 6h.01"/><circle cx="12" cy="14" r="4"/><path d="M12 14h.01"/>`),
		scan.KindConsole:  icon(`<line x1="6" x2="10" y1="11" y2="11"/><line x1="8" x2="8" y1="9" y2="13"/><line x1="15" x2="15.01" y1="12" y2="12"/><line x1="18" x2="18.01" y1="10" y2="10"/><path d="M17.32 5H6.68a4 4 0 0 0-3.978 3.59C2.604 9.416 2 14.456 2 16a3 3 0 0 0 3 3c1 0 1.5-.5 2-1l1.414-1.414A2 2 0 0 1 9.828 16h4.344a2 2 0 0 1 1.414.586L17 18c.5.5 1 1 2 1a3 3 0 0 0 3-3c0-1.545-.604-6.584-.685-7.258A4 4 0 0 0 17.32 5z"/>`),
		scan.KindIoT:      icon(`<path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/>`),
		scan.KindServer:   icon(`<rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/>`),
	}
)

// kindColor gives each kind of device a hue of its own, as light in the
// dark theme as the text around it.
func kindColor(t *ui.Theme, k scan.Kind) ui.Color {
	hue := map[scan.Kind]float32{
		scan.KindRouter:   300,
		scan.KindComputer: 250,
		scan.KindPhone:    150,
		scan.KindTablet:   175,
		scan.KindPrinter:  60,
		scan.KindCamera:   25,
		scan.KindTV:       350,
		scan.KindNAS:      200,
		scan.KindSpeaker:  320,
		scan.KindConsole:  275,
		scan.KindIoT:      85,
		scan.KindServer:   225,
	}
	h, ok := hue[k]
	if !ok {
		return t.TextMuted
	}
	if t.Dark {
		return ui.Oklch(0.75, 0.13, h)
	}
	return ui.Oklch(0.55, 0.15, h)
}
