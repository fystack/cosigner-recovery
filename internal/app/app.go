package app

import (
	"context"
	"io/fs"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"recovery/internal/recovery"
)

// App is the Wails-bound backend; its exported methods are the frontend API.
type App struct {
	ctx     context.Context
	session *recovery.Session
	sweep   sweepState
}

func New() *App {
	return &App{session: recovery.NewSession()}
}

// Run starts the desktop window serving the given frontend assets.
func Run(assets fs.FS) error {
	app := New()
	return wails.Run(&options.App{
		Title:            "Fystack Recovery",
		Width:            1024,
		Height:           768,
		MinWidth:         720,
		MinHeight:        560,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 255, G: 255, B: 255, A: 1},
		OnStartup:        app.startup,
		Bind:             []interface{}{app},
	})
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) Status() recovery.Status { return a.session.Status() }

func (a *App) Recover() ([]*recovery.CombinedKey, error) { return a.session.Recover() }

func (a *App) Reset() { a.session.Reset() }

// CopyToClipboard puts text on the clipboard (frontend clears it after a delay).
func (a *App) CopyToClipboard(text string) error {
	return runtime.ClipboardSetText(a.ctx, text)
}

func (a *App) ClearClipboard() error {
	return runtime.ClipboardSetText(a.ctx, "")
}
