package rawblock_test

import (
	"image/color"
	"net/url"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"
	fyneTest "fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"

	"lighthouse-in-snoo/internal/ui/rawblock"
)

func TestThemeTokensZeroRadiusZeroShadowAndEmbeddedFonts(t *testing.T) {
	th := rawblock.NewTheme()

	// Every radius token MUST be strictly 0px (no rounding anywhere).
	for _, sn := range []fyne.ThemeSizeName{
		theme.SizeNameButtonRadius,
		theme.SizeNameCardRadius,
		theme.SizeNameDialogRadius,
		theme.SizeNamePopupRadius,
		theme.SizeNameMenuRadius,
		theme.SizeNameInputRadius,
		theme.SizeNameSelectionRadius,
		theme.SizeNameScrollBarRadius,
		theme.SizeNameInnerWindowRadius,
		theme.SizeNameWindowButtonRadius,
		theme.SizeNameModalBlurRadius,
	} {
		if got := th.Size(sn); got != 0 {
			t.Fatalf("RawBlock radius token %q = %v; want 0", sn, got)
		}
	}

	// Shadows MUST be completely transparent.
	if got := th.Color(theme.ColorNameShadow, theme.VariantLight); got != color.Transparent {
		t.Fatalf("shadow color = %v; want transparent", got)
	}
	// Hyperlink blue is strictly #0000FF; background is #FFFFFF; foreground is #000000.
	if th.Color(theme.ColorNameHyperlink, theme.VariantLight) != rawblock.ColorBlue {
		t.Fatal("hyperlink color mismatch")
	}
	if th.Color(theme.ColorNameBackground, theme.VariantDark) != rawblock.ColorWhite {
		t.Fatal("RawBlock background must stay #FFFFFF regardless of OS variant")
	}
	if th.Color(theme.ColorNameForeground, theme.VariantDark) != rawblock.ColorBlack {
		t.Fatal("RawBlock foreground must stay #000000 regardless of OS variant")
	}

	// Every text size token and theme text size MUST enforce the 14px minimum floor.
	for _, sz := range []float32{
		rawblock.TextMin,
		rawblock.TextH1,
		rawblock.TextH2,
		rawblock.TextH3,
		rawblock.TextH4,
		rawblock.TextBody,
		rawblock.TextMono,
		rawblock.TextSmall,
		rawblock.TextTooltip,
		rawblock.TextTiny,
		rawblock.TextStatusChip,
		rawblock.TextFilterChip,
		th.Size(theme.SizeNameText),
		th.Size(theme.SizeNameCaptionText),
		th.Size(theme.SizeNameHeadingText),
		th.Size(theme.SizeNameSubHeadingText),
		rawblock.NewTiny("caption", rawblock.ColorBlack).TextSize,
		rawblock.NewTrackedText("CLAMP", 8, rawblock.StyleBody, rawblock.ColorBlack, 1).TextSize,
	} {
		if sz < 14 {
			t.Fatalf("font size %v violates 14px minimum", sz)
		}
	}

	// Verify all 5 embedded SIL-OFL font styles resolve non-empty TrueType data.
	for _, st := range []fyne.TextStyle{
		rawblock.StyleBody,
		rawblock.StyleHeadline,
		rawblock.StyleSemiBold,
		rawblock.StyleMono,
		rawblock.StyleMonoBold,
	} {
		res := th.Font(st)
		if res == nil || len(res.Content()) < 1024 {
			t.Fatalf("missing or invalid embedded font for style %+v", st)
		}
	}
}

func TestButtonsVariantsSizesHoverActiveAndDisabled(t *testing.T) {
	a := fyneTest.NewTempApp(t)
	a.Settings().SetTheme(rawblock.NewTheme())

	tapped := 0
	primary := rawblock.NewButton("submit", rawblock.ButtonPrimary, rawblock.ButtonMedium, func() { tapped++ })
	w := a.NewWindow("test")
	w.SetContent(primary)

	if primary.Text != "SUBMIT" {
		t.Fatalf("expected uppercase text, got %q", primary.Text)
	}
	if h := primary.MinSize().Height; h < 44 {
		t.Fatalf("medium button min height = %v; want >= 44", h)
	}

	// Default Primary: black fill, white text, 3px border.
	fill, fg, border, bw := primary.StyleColors()
	if fill != rawblock.ColorBlack || fg != rawblock.ColorWhite || border != rawblock.ColorBlack || bw != rawblock.BorderThick {
		t.Fatalf("unexpected primary default style: %v %v %v %v", fill, fg, border, bw)
	}

	// Hover Primary: full inversion (white fill, black text).
	primary.MouseIn(&desktop.MouseEvent{})
	fill, fg, _, bw = primary.StyleColors()
	if fill != rawblock.ColorWhite || fg != rawblock.ColorBlack || bw != rawblock.BorderThick {
		t.Fatalf("primary hover must invert to white/black, got %v %v %v", fill, fg, bw)
	}

	// Active/Pressed Primary: black fill, white text, 5px border.
	primary.MouseDown(&desktop.MouseEvent{})
	fill, fg, _, bw = primary.StyleColors()
	if fill != rawblock.ColorBlack || fg != rawblock.ColorWhite || bw != rawblock.BorderHeavy {
		t.Fatalf("primary active must use 5px border, got %v %v %v", fill, fg, bw)
	}
	primary.MouseUp(&desktop.MouseEvent{})
	primary.MouseOut()

	fyneTest.Tap(primary)
	if tapped != 1 {
		t.Fatalf("tapped = %d; want 1", tapped)
	}

	// Disabled Primary: sunken fill, tertiary text, #CCCCCC border (no opacity), ignores tap.
	primary.Disable()
	fill, fg, border, bw = primary.StyleColors()
	if fill != rawblock.ColorSurfaceSunken || fg != rawblock.ColorContentTertiary || border != rawblock.ColorBorderDisabled || bw != rawblock.BorderThick {
		t.Fatalf("unexpected disabled style: %v %v %v %v", fill, fg, border, bw)
	}
	fyneTest.Tap(primary)
	if tapped != 1 {
		t.Fatalf("disabled button must ignore tap")
	}

	// Secondary, Ghost, Destructive + Small/Large sizes.
	sec := rawblock.NewButton("cancel", rawblock.ButtonSecondary, rawblock.ButtonSmall, nil)
	if sec.TextSize() < rawblock.TextMin {
		t.Fatalf("small button text size = %v; want >= %v", sec.TextSize(), rawblock.TextMin)
	}
	if sec.MinSize().Height < 32 {
		t.Fatalf("small button height = %v; want >= 32", sec.MinSize().Height)
	}
	sec.MouseIn(&desktop.MouseEvent{})
	if f, g, _, _ := sec.StyleColors(); f != rawblock.ColorBlack || g != rawblock.ColorWhite {
		t.Fatal("secondary hover must invert to black/white")
	}

	ghost := rawblock.NewButton("more", rawblock.ButtonGhost, rawblock.ButtonMedium, nil)
	ghost.MouseIn(&desktop.MouseEvent{})
	if _, g, _, bw := ghost.StyleColors(); g != rawblock.ColorBlue || bw != 0 {
		t.Fatal("ghost hover must turn link blue with 0px border")
	}

	destr := rawblock.NewButton("delete", rawblock.ButtonDestructive, rawblock.ButtonLarge, nil)
	if destr.MinSize().Height < 56 {
		t.Fatalf("large button height = %v; want >= 56", destr.MinSize().Height)
	}
	if f, g, _, _ := destr.StyleColors(); f != rawblock.ColorError || g != rawblock.ColorWhite {
		t.Fatal("destructive default must be error red fill + white text")
	}
	destr.MouseIn(&desktop.MouseEvent{})
	if f, g, _, _ := destr.StyleColors(); f != rawblock.ColorBlack || g != rawblock.ColorError {
		t.Fatal("destructive hover must invert to black fill + error red text")
	}
}

func TestCardsInputsChipsListCheckRadioTooltipAndLink(t *testing.T) {
	a := fyneTest.NewTempApp(t)
	a.Settings().SetTheme(rawblock.NewTheme())
	w := a.NewWindow("specimen")

	// Cards: Default 3px, Elevated 5px, Inverted black fill.
	cDef := rawblock.NewCard(rawblock.NewBody("body", rawblock.ColorBlack), rawblock.CardDefault)
	cElv := rawblock.NewCard(rawblock.NewBody("body", rawblock.ColorBlack), rawblock.CardElevated)
	cInv := rawblock.NewCard(rawblock.NewBody("body", rawblock.ColorWhite), rawblock.CardInverted)
	if _, _, bw := cDef.StyleSpec(); bw != rawblock.BorderThick {
		t.Fatalf("default card border = %v; want 3", bw)
	}
	if _, _, bw := cElv.StyleSpec(); bw != rawblock.BorderHeavy {
		t.Fatalf("elevated card border = %v; want 5", bw)
	}
	if fill, _, _ := cInv.StyleSpec(); fill != rawblock.ColorBlack {
		t.Fatalf("inverted card fill = %v; want black", fill)
	}

	// Input: Default (#F0F0F0/3px), Error (#FF0000), Disabled (#F5F5F5/#CCCCCC).
	in := rawblock.NewInput("endpoint", "wss://...", "helper", false)
	if fill, border, bw := in.FrameStyle(); fill != rawblock.ColorSurfaceSunken || border != rawblock.ColorBlack || bw != rawblock.BorderThick {
		t.Fatalf("unexpected input default style: %v %v %v", fill, border, bw)
	}
	in.SetError("invalid url")
	if _, border, _ := in.FrameStyle(); border != rawblock.ColorError {
		t.Fatalf("expected error border, got %v", border)
	}
	in.Disable()
	if fill, border, _ := in.FrameStyle(); fill != rawblock.ColorSurfaceDisabled || border != rawblock.ColorBorderDisabled {
		t.Fatalf("unexpected input disabled style: %v %v", fill, border)
	}
	in.Enable()
	in.SetError("")

	// Password input must suppress Fyne's trailing eye icon via a hidden non-nil ActionItem.
	passIn := rawblock.NewInput("", "secret", "", true)
	if passIn.Entry.ActionItem == nil || passIn.Entry.ActionItem.Visible() {
		t.Fatal("password input must replace trailing eye icon with hidden placeholder")
	}
	if h := passIn.MinSize().Height; h != 44 {
		t.Fatalf("unlabeled input height = %v; want 44 (flush with ButtonMedium)", h)
	}

	// Chips: Filter inversion + Status tones.
	fc := rawblock.NewFilterChip("all", false, nil)
	if f, g, _ := fc.StyleColors(); f != rawblock.ColorWhite || g != rawblock.ColorBlack {
		t.Fatal("inactive filter chip must be white/black")
	}
	fc.SetActive(true)
	if f, g, _ := fc.StyleColors(); f != rawblock.ColorBlack || g != rawblock.ColorWhite {
		t.Fatal("active filter chip must invert to black/white")
	}
	for _, tc := range []struct {
		tone rawblock.ChipTone
		want color.Color
	}{
		{rawblock.ChipActive, rawblock.ColorSuccess},
		{rawblock.ChipWarning, rawblock.ColorWarning},
		{rawblock.ChipError, rawblock.ColorError},
		{rawblock.ChipDefault, rawblock.ColorBlack},
	} {
		sc := rawblock.NewStatusChip("status", tc.tone)
		if f, fg, br := sc.StyleColors(); f != rawblock.ColorWhite || fg != tc.want || br != tc.want {
			t.Fatalf("status chip tone %v = (%v,%v,%v)", tc.tone, f, fg, br)
		}
	}

	// List: hover underline + active full-width black fill.
	selectedIdx := -1
	lst := rawblock.NewList([]string{"Item One", "Item Two", "Item Three"}, func(i int, _ string) {
		selectedIdx = i
	})
	lst.Select(1)
	if selectedIdx != 1 || lst.Selected != 1 {
		t.Fatalf("list selection failed: %d", selectedIdx)
	}
	row := rawblock.NewListItem("Hover Row", nil)
	row.MouseIn(&desktop.MouseEvent{})
	if fill, fg, ul := row.VisualState(); fill != color.Transparent || fg != rawblock.ColorBlack || !ul {
		t.Fatalf("list hover must underline: %v %v %v", fill, fg, ul)
	}
	row.SetActive(true)
	if fill, fg, ul := row.VisualState(); fill != rawblock.ColorBlack || fg != rawblock.ColorWhite || ul {
		t.Fatalf("list active must invert black/white: %v %v %v", fill, fg, ul)
	}

	// Checkbox: 20x20 square, toggle, 5px focus, disabled.
	chkChanged := false
	chk := rawblock.NewCheck("accept", func(v bool) { chkChanged = v })
	fyneTest.Tap(chk)
	if !chk.Checked || !chkChanged {
		t.Fatal("checkbox tap failed")
	}
	chk.FocusGained()
	if fill, _, bw := chk.BoxStyle(); fill != rawblock.ColorBlack || bw != rawblock.BorderHeavy {
		t.Fatalf("focused checked box = (%v, %v); want (black, 5)", fill, bw)
	}
	chk.Disable()
	if fill, border, _ := chk.BoxStyle(); fill != rawblock.ColorSurfaceDisabled || border != rawblock.ColorBorderDisabled {
		t.Fatalf("disabled checkbox = (%v, %v)", fill, border)
	}

	// RadioGroup: circular single-selection, 5px focus, disabled.
	gotRadio := ""
	rg := rawblock.NewRadioGroup([]string{"UDP", "TCP"}, "UDP", func(v string) { gotRadio = v })
	rg.SetSelected("TCP")
	if rg.Selected != "TCP" || gotRadio != "TCP" {
		t.Fatalf("radio selection failed: %q / %q", rg.Selected, gotRadio)
	}
	ro := rawblock.NewRadioOption("Option A", true, nil)
	ro.FocusGained()
	if _, _, _, bw := ro.CircleStyle(); bw != rawblock.BorderHeavy {
		t.Fatalf("focused radio border = %v; want 5", bw)
	}
	ro.Disable()
	if fill, border, _, _ := ro.CircleStyle(); fill != rawblock.ColorSurfaceDisabled || border != rawblock.ColorBorderDisabled {
		t.Fatalf("disabled radio = (%v, %v)", fill, border)
	}

	// Tooltip: <= 260px width, shows on hover and hides on MouseOut.
	tip := rawblock.NewTooltip("Cryptographically verified peer identifier bound to an RFC 6598 virtual IP address.")
	if ms := tip.MinSize(); ms.Width > 260 {
		t.Fatalf("tooltip width %v exceeds 260px max width", ms.Width)
	}
	tw := rawblock.WithTooltip(rawblock.NewMono("PEER", rawblock.ColorBlack), "TOOLTIP TEXT")
	w.SetContent(rawblock.GapVBox(rawblock.Sp2, cDef, in, fc, lst, chk, rg, tw))
	w.Resize(fyne.NewSize(600, 600))
	tw.MouseIn(&desktop.MouseEvent{})
	if !tw.Showing() {
		t.Fatal("expected tooltip to show on MouseIn")
	}
	tw.MouseOut()
	if tw.Showing() {
		t.Fatal("expected tooltip to hide on MouseOut")
	}

	// Link: reserved hyperlink blue.
	u, _ := url.Parse("https://example.com")
	linkTapped := false
	lnk := rawblock.NewLink("SPECIFICATION", u, func() { linkTapped = true })
	fyneTest.Tap(lnk)
	if !linkTapped {
		t.Fatal("link tap failed")
	}
}
