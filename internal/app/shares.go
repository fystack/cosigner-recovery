package app

import (
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"recovery/internal/recovery"
)

var shareFilters = []runtime.FileFilter{
	{DisplayName: "Share files (*.enc, *.mshare, *.json)", Pattern: "*.enc;*.mshare;*.json"},
	allFiles,
}

// AddShareFile opens a file picker and registers the chosen share file.
func (a *App) AddShareFile() (recovery.ShareInfo, error) {
	path, err := a.pickFile("Select a share file", shareFilters...)
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
	path, err := a.pickFile("Select the RSA private key (PEM)", pemFilters...)
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
	defer wipeBytes(pemData)
	return a.session.UnlockShare(id, string(pemData))
}

// UnlockWithRSAKeyText unlocks the share with a pasted PEM private key.
func (a *App) UnlockWithRSAKeyText(id, pem string) (recovery.ShareInfo, error) {
	return a.session.UnlockShare(id, pem)
}

func (a *App) RemoveShare(id string) { a.session.RemoveShare(id) }
