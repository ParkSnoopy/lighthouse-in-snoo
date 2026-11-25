package ui

import (
	_ "embed"

	"fyne.io/fyne/v2"
)

const (
	// AppID is the canonical application ID shared across Fyne, Wayland xdg-shell app_id,
	// X11 StartupWMClass, Freedesktop .desktop / hicolor icons, and macOS CFBundleIdentifier.
	AppID = "us.ireh.lighthouse"

	// AppName is the user-facing desktop application name.
	AppName = "Lighthouse"
)

//go:embed assets/icon-48.png
var icon48PNG []byte

//go:embed assets/icon-128.png
var icon128PNG []byte

//go:embed assets/icon-256.png
var icon256PNG []byte

//go:embed assets/icon-512.png
var icon512PNG []byte

var appIconResource = fyne.NewStaticResource("lighthouse-in-snoo.png", icon512PNG)

// AppIcon returns the embedded 512x512 RGBA PNG Fyne resource used for X11 (_NET_WM_ICON),
// Windows (WM_SETICON), and Fyne application metadata.
func AppIcon() fyne.Resource {
	return appIconResource
}

// IconPNG returns embedded Lanczos-scaled RGBA PNG icon bytes for size (48, 128, 256, or 512).
func IconPNG(size int) []byte {
	switch size {
	case 48:
		return icon48PNG
	case 128:
		return icon128PNG
	case 256:
		return icon256PNG
	default:
		return icon512PNG
	}
}

// ApplyRuntimePlatformIcon installs or applies OS-native runtime icon bindings:
//   - Linux (Wayland & X11): ensures user XDG hicolor PNG icons and us.ireh.lighthouse.desktop
//     exist so Wayland compositors match WaylandAppID ("us.ireh.lighthouse") automatically.
//   - macOS (cgo): sets NSApplication.applicationIconImage for the live Dock icon.
//   - Windows: runtime titlebar/taskbar icon is applied via fyne.App/Window SetIcon and
//     PE explorer/taskbar icon is linked via cmd/lighthouse-ui/icon_windows_{amd64,arm64}.syso.
func ApplyRuntimePlatformIcon() {
	applyPlatformIcon(icon512PNG)
}
