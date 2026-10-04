package app

import (
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"recovery/internal/recovery"
)

var childExportFilters = []runtime.FileFilter{
	{DisplayName: "JSON (for recover-cli)", Pattern: "*.json"},
	{DisplayName: "CSV (for import)", Pattern: "*.csv"},
}

// ExportKey writes a recovered private key to a user-chosen file.
func (a *App) ExportKey(protocol, content string) (string, error) {
	path, err := a.pickSavePath("Export "+protocol+" private key", protocol+"-private-key.txt")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, []byte(content), 0o600)
}

// ExportChildKeys derives the master and all child keys and writes them to a file (.csv or .json).
func (a *App) ExportChildKeys() (string, error) {
	keys, err := a.session.DeriveChildKeys()
	if err != nil {
		return "", err
	}
	path, err := a.pickSavePath("Export child wallet keys", "child-keys.json", childExportFilters...)
	if err != nil {
		return "", err
	}
	return path, recovery.WriteChildKeys(path, keys)
}

// ExportKeystores writes the master and child ECDSA keys as password-encrypted keystore files into a chosen folder.
func (a *App) ExportKeystores(password string) (string, error) {
	keys, err := a.session.DeriveChildKeys()
	if err != nil {
		return "", err
	}
	dir, err := a.pickDirectory("Choose a folder for the keystore files")
	if err != nil {
		return "", err
	}
	n, err := recovery.WriteKeystores(dir, password, keys)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d keystore files written to %s", n, dir), nil
}
