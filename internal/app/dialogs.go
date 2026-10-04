package app

import (
	"errors"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

var errExportCancelled = errors.New("export cancelled")

var (
	allFiles   = runtime.FileFilter{DisplayName: "All files", Pattern: "*.*"}
	pemFilters = []runtime.FileFilter{{DisplayName: "PEM key (*.pem, *.key)", Pattern: "*.pem;*.key"}, allFiles}
)

// pickFile returns "" when the user cancels the dialog.
func (a *App) pickFile(title string, filters ...runtime.FileFilter) (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{Title: title, Filters: filters})
}

func (a *App) pickDirectory(title string) (string, error) {
	dir, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{Title: title, CanCreateDirectories: true})
	if err != nil {
		return "", err
	}
	if dir == "" {
		return "", errExportCancelled
	}
	return dir, nil
}

func (a *App) pickSavePath(title, defaultName string, filters ...runtime.FileFilter) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           title,
		DefaultFilename: defaultName,
		Filters:         filters,
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", errExportCancelled
	}
	return path, nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
