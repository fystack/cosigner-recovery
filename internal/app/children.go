package app

import (
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"recovery/internal/recovery"
)

var childListFilters = []runtime.FileFilter{
	{DisplayName: "Child wallet list (*.enc, *.json)", Pattern: "*.enc;*.json"},
	allFiles,
}

// AddChildPathsFile picks the child wallet list file; it stays locked until UnlockChildPaths.
func (a *App) AddChildPathsFile() (recovery.HDInfo, error) {
	path, err := a.pickFile("Select the child wallet list file", childListFilters...)
	if err != nil || path == "" {
		return a.session.HDInfo(), err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return recovery.HDInfo{}, err
	}
	return a.session.AddHDFile(raw, filepath.Base(path))
}

// UnlockChildPaths picks the RSA private key and opens the pending child wallet list.
func (a *App) UnlockChildPaths() (recovery.HDInfo, error) {
	path, err := a.pickFile("Select the RSA private key (PEM)", pemFilters...)
	if err != nil || path == "" {
		return a.session.HDInfo(), err
	}
	pemData, err := os.ReadFile(path)
	if err != nil {
		return recovery.HDInfo{}, err
	}
	defer wipeBytes(pemData)
	return a.session.UnlockHD(pemData)
}

func (a *App) RemoveChildPaths() { a.session.RemoveHD() }

func (a *App) HDStatus() recovery.HDInfo { return a.session.HDInfo() }
