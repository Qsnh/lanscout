// LanScout finds the devices on the local network and the addresses they
// use, to hand out IP addresses without conflicts. Its window is native UI
// that MyGo draws on the GPU: Metal on macOS, Direct3D 11 on Windows.
package main

import (
	"log"

	"github.com/egoist/mygo"
	_ "github.com/egoist/mygo/locales/zh-Hans"
	"github.com/egoist/mygo/ui"
)

func main() {
	// The app is written in Chinese: MyGo's own controls and menus say
	// Chinese too, as the search field's placeholder and the Edit menu.
	mygo.App.SetLanguages("zh-Hans")
	a := newApp()
	mygo.App.WhenReady(func() {
		win := mygo.NewWindow(mygo.WindowOptions{
			Title:     "LanScout",
			Width:     1240,
			Height:    800,
			MinWidth:  980,
			MinHeight: 620,
			// Opens where the user left it last time.
			StateKey: "main",
			Content:  ui.View(a.view),
		})
		a.post = win.Update
		a.save = func(name string) (string, error) {
			return mygo.Dialog.Save(mygo.SaveDialogOptions{
				Parent:      win,
				Title:       "导出扫描结果",
				DefaultPath: name,
				Filters:     []mygo.FileFilter{{Name: "CSV 表格", Extensions: []string{"csv"}}},
			})
		}
		// The window opens on a scan of the network it is on.
		win.Update(a.startScan)
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
