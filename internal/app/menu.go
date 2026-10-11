package app

import (
	goruntime "runtime"

	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ZoomEvent is emitted to the frontend with "in", "out" or "reset".
const ZoomEvent = "zoom"

func (a *App) menu() *menu.Menu {
	m := menu.NewMenu()
	if goruntime.GOOS == "darwin" {
		// Replacing the default menu drops Cmd+C/V unless these roles are kept.
		m.Append(menu.AppMenu())
		m.Append(menu.EditMenu())
	}

	zoom := func(dir string) menu.Callback {
		return func(*menu.CallbackData) { runtime.EventsEmit(a.ctx, ZoomEvent, dir) }
	}
	view := m.AddSubmenu("View")
	view.AddText("Zoom In", keys.CmdOrCtrl("="), zoom("in"))
	view.AddText("Zoom Out", keys.CmdOrCtrl("-"), zoom("out"))
	view.AddSeparator()
	view.AddText("Reset Zoom", keys.CmdOrCtrl("0"), zoom("reset"))
	return m
}
