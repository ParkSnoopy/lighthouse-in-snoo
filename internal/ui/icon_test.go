package ui_test

import (
	"bytes"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	fyneTest "fyne.io/fyne/v2/test"

	"lighthouse-in-snoo/internal/ui"
)

type iconRecordingApp struct {
	fyne.App
	appIcon fyne.Resource
	win     *iconRecordingWindow
}

func (a *iconRecordingApp) SetIcon(r fyne.Resource) { a.appIcon = r }
func (a *iconRecordingApp) Icon() fyne.Resource     { return a.appIcon }
func (a *iconRecordingApp) NewWindow(title string) fyne.Window {
	w := &iconRecordingWindow{Window: a.App.NewWindow(title)}
	a.win = w
	return w
}

type iconRecordingWindow struct {
	fyne.Window
	winIcon fyne.Resource
}

func (w *iconRecordingWindow) SetIcon(r fyne.Resource) { w.winIcon = r }
func (w *iconRecordingWindow) Icon() fyne.Resource     { return w.winIcon }

func TestAppIconResourceAndControllerBinding(t *testing.T) {
	if ui.AppID != "us.ireh.lighthouse" {
		t.Fatalf("AppID = %q; want us.ireh.lighthouse", ui.AppID)
	}
	res := ui.AppIcon()
	if res == nil || len(res.Content()) == 0 {
		t.Fatal("AppIcon returned empty resource")
	}
	img, err := png.Decode(bytes.NewReader(res.Content()))
	if err != nil {
		t.Fatalf("decode AppIcon PNG: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 512 || b.Dy() != 512 {
		t.Fatalf("AppIcon dimensions = %dx%d; want 512x512", b.Dx(), b.Dy())
	}

	for _, sz := range []int{48, 128, 256, 512} {
		data := ui.IconPNG(sz)
		decoded, decErr := png.Decode(bytes.NewReader(data))
		if decErr != nil {
			t.Fatalf("decode IconPNG(%d): %v", sz, decErr)
		}
		if b := decoded.Bounds(); b.Dx() != sz || b.Dy() != sz {
			t.Fatalf("IconPNG(%d) dimensions = %dx%d", sz, b.Dx(), b.Dy())
		}
	}

	recApp := &iconRecordingApp{App: fyneTest.NewTempApp(t)}
	ctrl, err := ui.NewController(recApp, ui.Options{
		BlacklistPath: filepath.Join(t.TempDir(), "bl.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Disconnect()

	if recApp.Icon() == nil || len(recApp.Icon().Content()) == 0 {
		t.Fatal("expected NewController to call app.SetIcon")
	}
	if recApp.win == nil || recApp.win.Icon() == nil || len(recApp.win.Icon().Content()) == 0 {
		t.Fatal("expected NewController to call window.SetIcon")
	}
	if ctrl.MastheadIcon == nil || ctrl.MastheadIcon.Resource == nil || len(ctrl.MastheadIcon.Resource.Content()) == 0 {
		t.Fatal("expected MastheadIcon to be mounted with embedded app icon resource")
	}
	if ctrl.MastheadIcon.FillMode != canvas.ImageFillContain {
		t.Fatalf("MastheadIcon.FillMode = %v; want ImageFillContain", ctrl.MastheadIcon.FillMode)
	}
	if ms := ctrl.MastheadIcon.MinSize(); ms.Width < 40 || ms.Width != ms.Height {
		t.Fatalf("MastheadIcon.MinSize = %v; want square >= 40px", ms)
	}
}

func TestCrossPlatformIconAssetsPresent(t *testing.T) {
	root := filepath.Join("..", "..")

	// Windows ICO header: reserved(0), type(1), count >= 5.
	ico, err := os.ReadFile(filepath.Join(root, "assets", "icon", "lighthouse-in-snoo.ico"))
	if err != nil || len(ico) < 22 || ico[0] != 0 || ico[1] != 0 || ico[2] != 1 || ico[3] != 0 || ico[4] < 5 {
		t.Fatalf("invalid or missing Windows ICO asset: err=%v len=%d", err, len(ico))
	}

	// macOS ICNS header: magic "icns".
	icns, err := os.ReadFile(filepath.Join(root, "assets", "icon", "lighthouse-in-snoo.icns"))
	if err != nil || len(icns) < 16 || string(icns[:4]) != "icns" {
		t.Fatalf("invalid or missing macOS ICNS asset: err=%v len=%d", err, len(icns))
	}

	// Windows PE COFF .syso resources for amd64 (0x8664) and arm64 (0xAA64).
	for _, tc := range []struct {
		file string
		b0   byte
		b1   byte
	}{
		{"icon_windows_amd64.syso", 0x64, 0x86},
		{"icon_windows_arm64.syso", 0x64, 0xAA},
	} {
		raw, rErr := os.ReadFile(filepath.Join(root, "cmd", "lighthouse-ui", tc.file))
		if rErr != nil || len(raw) < 60 || raw[0] != tc.b0 || raw[1] != tc.b1 {
			t.Fatalf("invalid Windows COFF resource %s: err=%v len=%d", tc.file, rErr, len(raw))
		}
	}

	// Wayland/X11 Freedesktop desktop entry and macOS Info.plist.
	desktopRaw, err := os.ReadFile(filepath.Join(root, "assets", "packaging", "linux", ui.AppID+".desktop"))
	if err != nil || !strings.Contains(string(desktopRaw), "StartupWMClass="+ui.AppID) || !strings.Contains(string(desktopRaw), "Icon="+ui.AppID) {
		t.Fatalf("invalid Linux .desktop entry: err=%v", err)
	}
	plistRaw, err := os.ReadFile(filepath.Join(root, "assets", "packaging", "macos", "Info.plist"))
	if err != nil || !strings.Contains(string(plistRaw), "lighthouse-in-snoo.icns") || !strings.Contains(string(plistRaw), ui.AppID) {
		t.Fatalf("invalid macOS Info.plist: err=%v", err)
	}

	// Verify Linux Wayland/X11 XDG runtime icon installer writes all required files cleanly.
	if runtime.GOOS == "linux" {
		tmpData := t.TempDir()
		if err := ui.EnsureLinuxDesktopIcon(tmpData, "/opt/lighthouse/lighthouse-ui"); err != nil {
			t.Fatalf("EnsureLinuxDesktopIcon: %v", err)
		}
		for _, sz := range []string{"48x48", "128x128", "256x256", "512x512"} {
			p := filepath.Join(tmpData, "icons", "hicolor", sz, "apps", ui.AppID+".png")
			if st, sErr := os.Stat(p); sErr != nil || st.Size() == 0 {
				t.Fatalf("missing installed hicolor icon %s: %v", p, sErr)
			}
		}
		dp := filepath.Join(tmpData, "applications", ui.AppID+".desktop")
		content, rErr := os.ReadFile(dp)
		if rErr != nil || !strings.Contains(string(content), "Exec=/opt/lighthouse/lighthouse-ui") || !strings.Contains(string(content), "StartupWMClass="+ui.AppID) {
			t.Fatalf("unexpected installed desktop file: err=%v content=%s", rErr, string(content))
		}
	}
}
