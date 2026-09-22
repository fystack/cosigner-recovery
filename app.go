package main

import (
	"context"
	"errors"
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"recovery/internal/recovery"
)

type App struct {
	ctx     context.Context
	session *recovery.Session
}

func NewApp() *App {
	return &App{session: recovery.NewSession()}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// AddShareFile opens a file picker and registers the chosen share file.
func (a *App) AddShareFile() (recovery.ShareInfo, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select a share file",
		Filters: []runtime.FileFilter{
			{DisplayName: "Share files (*.enc, *.mshare, *.json)", Pattern: "*.enc;*.mshare;*.json"},
			{DisplayName: "All files", Pattern: "*.*"},
		},
	})
	if err != nil {
		return recovery.ShareInfo{}, err
	}
	if path == "" {
		return recovery.ShareInfo{Cancelled: true}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return recovery.ShareInfo{}, err
	}
	return a.session.AddShare(raw)
}

// UnlockWithPassphrase decrypts a pending .mshare with a passphrase.
func (a *App) UnlockWithPassphrase(id, passphrase string) (recovery.ShareInfo, error) {
	return a.session.UnlockShare(id, passphrase)
}

// UnlockWithRSAKeyFile opens a file picker for the RSA private key and unlocks the share.
func (a *App) UnlockWithRSAKeyFile(id string) (recovery.ShareInfo, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select the RSA private key (PEM)",
		Filters: []runtime.FileFilter{
			{DisplayName: "PEM key (*.pem, *.key)", Pattern: "*.pem;*.key"},
			{DisplayName: "All files", Pattern: "*.*"},
		},
	})
	if err != nil {
		return recovery.ShareInfo{}, err
	}
	if path == "" {
		return recovery.ShareInfo{Cancelled: true}, nil
	}
	pemData, err := os.ReadFile(path)
	if err != nil {
		return recovery.ShareInfo{}, err
	}
	info, err := a.session.UnlockShare(id, string(pemData))
	for i := range pemData {
		pemData[i] = 0
	}
	return info, err
}

// UnlockWithRSAKeyText unlocks the share with a pasted PEM private key.
func (a *App) UnlockWithRSAKeyText(id, pem string) (recovery.ShareInfo, error) {
	return a.session.UnlockShare(id, pem)
}

func (a *App) RemoveShare(id string) { a.session.RemoveShare(id) }

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

// ExportKey writes a recovered private key to a user-chosen file.
func (a *App) ExportKey(protocol, content string) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Export " + protocol + " private key",
		DefaultFilename: protocol + "-private-key.txt",
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", errors.New("export cancelled")
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}
