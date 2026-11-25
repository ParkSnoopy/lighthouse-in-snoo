//go:build linux

package ui

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func applyPlatformIcon(_ []byte) {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if strings.TrimSpace(dataHome) == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	execPath, err := os.Executable()
	if err != nil || execPath == "" {
		execPath = "lighthouse-ui"
	}
	_ = EnsureLinuxDesktopIcon(dataHome, execPath)
}

// EnsureLinuxDesktopIcon writes Freedesktop hicolor PNG icons (48, 128, 256, 512) and
// applications/us.ireh.lighthouse.desktop into dataHome so Wayland compositors (via
// xdg-shell app_id == "us.ireh.lighthouse") and X11 docks/launchers resolve the app icon.
func EnsureLinuxDesktopIcon(dataHome, execPath string) error {
	if strings.TrimSpace(dataHome) == "" {
		return fmt.Errorf("empty XDG data directory")
	}
	if strings.TrimSpace(execPath) == "" {
		execPath = "lighthouse-ui"
	}

	icons := []struct {
		dir  string
		data []byte
	}{
		{"48x48", icon48PNG},
		{"128x128", icon128PNG},
		{"256x256", icon256PNG},
		{"512x512", icon512PNG},
	}
	for _, ic := range icons {
		dst := filepath.Join(dataHome, "icons", "hicolor", ic.dir, "apps", AppID+".png")
		if err := writeIfChanged(dst, ic.data); err != nil {
			return err
		}
	}

	// Escape spaces per Freedesktop Desktop Entry Exec specification.
	escapedExec := execPath
	if strings.ContainsAny(escapedExec, " \t") {
		escapedExec = `"` + strings.ReplaceAll(escapedExec, `"`, `\"`) + `"`
	}
	desktopEntry := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=%s
Comment=Zero-config peer-to-peer TUN virtual network interface
Exec=%s
Icon=%s
Terminal=false
Categories=Network;Utility;
StartupWMClass=%s
`, AppName, escapedExec, AppID, AppID)

	desktopPath := filepath.Join(dataHome, "applications", AppID+".desktop")
	return writeIfChanged(desktopPath, []byte(desktopEntry))
}

func writeIfChanged(path string, content []byte) error {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, content) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o644)
}
