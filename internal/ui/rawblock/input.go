package rawblock

import (
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

type rawEntry struct {
	widget.Entry
	onStateChange func(focused, hovered bool)
	focused       bool
	hovered       bool
}

func newRawEntry(placeholder string, password bool, onStateChange func(focused, hovered bool)) *rawEntry {
	e := &rawEntry{onStateChange: onStateChange}
	e.PlaceHolder = placeholder
	e.Password = password
	if password {
		// Suppress Fyne's default trailing eye icon so inputs stay strictly icon-free per RawBlock.
		noIcon := canvas.NewRectangle(color.Transparent)
		noIcon.Hide()
		e.ActionItem = noIcon
	}
	e.TextStyle = StyleMono
	e.ExtendBaseWidget(e)
	return e
}

func (e *rawEntry) FocusGained() {
	e.Entry.FocusGained()
	e.focused = true
	if e.onStateChange != nil {
		e.onStateChange(e.focused, e.hovered)
	}
}

func (e *rawEntry) FocusLost() {
	e.Entry.FocusLost()
	e.focused = false
	if e.onStateChange != nil {
		e.onStateChange(e.focused, e.hovered)
	}
}

func (e *rawEntry) MouseIn(_ *desktop.MouseEvent) {
	e.hovered = true
	if e.onStateChange != nil {
		e.onStateChange(e.focused, e.hovered)
	}
}

func (e *rawEntry) MouseMoved(_ *desktop.MouseEvent) {}

func (e *rawEntry) MouseOut() {
	e.hovered = false
	if e.onStateChange != nil {
		e.onStateChange(e.focused, e.hovered)
	}
}

// Input implements RawBlock text/password fields:
//   - Surface sunken (#F0F0F0), Space Mono 15px, 10px/12px padding, razor-sharp 0px square corners
//   - Default: 3px black border; Hover: #E8E8E8 bg; Focus: 5px black border
//   - Error: 3px #FF0000 border; Disabled: 3px #CCCCCC border + #F5F5F5 bg (no double inner border)
//   - Label: Archivo Black 14px uppercase (4px margin-bottom)
//   - Helper/Error text: Work Sans 14px (4px margin-top)
type Input struct {
	widget.BaseWidget

	Entry      *widget.Entry
	labelText  string
	helperText string
	errText    string

	inner       *rawEntry
	outerBorder *canvas.Rectangle
	innerBG     *canvas.Rectangle
	disabledTxt *canvas.Text
	lbl         *canvas.Text
	helper      *canvas.Text
	focused     bool
	hovered     bool
}

var _ fyne.Disableable = (*Input)(nil)

// NewInput creates a labeled RawBlock Input widget.
func NewInput(label, placeholder, helper string, password bool) *Input {
	ri := &Input{
		labelText:  strings.ToUpper(label),
		helperText: helper,
	}
	ri.inner = newRawEntry(placeholder, password, func(focused, hovered bool) {
		ri.focused = focused
		ri.hovered = hovered
		ri.Refresh()
	})
	ri.Entry = &ri.inner.Entry
	ri.outerBorder = canvas.NewRectangle(ColorBlack)
	ri.outerBorder.CornerRadius = RadiusNone
	ri.innerBG = canvas.NewRectangle(ColorSurfaceSunken)
	ri.innerBG.CornerRadius = RadiusNone
	ri.disabledTxt = NewMono("", ColorContentTertiary)
	ri.disabledTxt.Hide()

	ri.lbl = NewLabel(ri.labelText, ColorBlack)
	ri.helper = NewTiny(ri.helperText, ColorContentSecondary)
	ri.ExtendBaseWidget(ri)
	return ri
}

// SetText sets the underlying entry value.
func (ri *Input) SetText(s string) {
	ri.Entry.SetText(s)
	if ri.Disabled() {
		ri.Refresh()
	}
}

// Text returns the current entry text.
func (ri *Input) Text() string { return ri.Entry.Text }

// SetError activates error border (#FF0000) and error helper text (clears if empty).
func (ri *Input) SetError(msg string) {
	ri.errText = msg
	ri.Refresh()
}

// SetHelper updates the default Work Sans 12px helper text.
func (ri *Input) SetHelper(msg string) {
	ri.helperText = msg
	ri.Refresh()
}

// Disable disables the input with #F5F5F5 background and 3px #CCCCCC border.
func (ri *Input) Disable() {
	ri.inner.Disable()
	ri.focused = false
	ri.hovered = false
	ri.Refresh()
}

// Enable re-enables the input.
func (ri *Input) Enable() {
	ri.inner.Enable()
	ri.Refresh()
}

// Disabled reports whether the input is disabled.
func (ri *Input) Disabled() bool { return ri.inner.Disabled() }

// FrameStyle returns current (fill, borderColor, borderWidth) for rendering and tests.
func (ri *Input) FrameStyle() (fill, border color.Color, borderW float32) {
	switch {
	case ri.inner.Disabled():
		return ColorSurfaceDisabled, ColorBorderDisabled, BorderThick
	case ri.errText != "":
		return ColorSurfaceSunken, ColorError, BorderThick
	case ri.focused:
		return ColorSurfaceSunken, ColorBlack, BorderHeavy
	case ri.hovered:
		return ColorSurfaceHover, ColorBlack, BorderThick
	default:
		return ColorSurfaceSunken, ColorBlack, BorderThick
	}
}

func (ri *Input) CreateRenderer() fyne.WidgetRenderer {
	innerThemed := container.NewThemeOverride(ri.inner, &inputInnerTheme{})
	r := &inputRenderer{
		ri:          ri,
		innerThemed: innerThemed,
	}
	r.Refresh()
	return r
}

type inputRenderer struct {
	ri          *Input
	innerThemed fyne.CanvasObject
}

func (r *inputRenderer) Destroy() {}

func (r *inputRenderer) Objects() []fyne.CanvasObject {
	objs := make([]fyne.CanvasObject, 0, 6)
	if r.ri.labelText != "" {
		objs = append(objs, r.ri.lbl)
	}
	objs = append(objs, r.ri.outerBorder, r.ri.innerBG, r.innerThemed, r.ri.disabledTxt)
	if r.ri.helperText != "" || r.ri.errText != "" {
		objs = append(objs, r.ri.helper)
	}
	return objs
}

func (r *inputRenderer) MinSize() fyne.Size {
	inMin := r.innerThemed.MinSize()
	w := max(inMin.Width+24, 140)
	h := max(inMin.Height+BorderThick*2, 44)
	if r.ri.labelText != "" {
		ls := fyne.MeasureText(r.ri.labelText, TextSmall, StyleHeadline)
		w = max(w, ls.Width)
		h += ls.Height + Sp1
	}
	if r.ri.helperText != "" || r.ri.errText != "" {
		hs := fyne.MeasureText(r.ri.helper.Text, TextTiny, StyleBody)
		h += hs.Height + Sp1
	}
	return fyne.NewSize(w, h)
}

func (r *inputRenderer) Layout(size fyne.Size) {
	_, _, bw := r.ri.FrameStyle()
	y := float32(0)
	if r.ri.labelText != "" {
		ls := fyne.MeasureText(r.ri.labelText, TextSmall, StyleHeadline)
		r.ri.lbl.Move(fyne.NewPos(0, y))
		r.ri.lbl.Resize(fyne.NewSize(size.Width, ls.Height))
		y += ls.Height + Sp1
	}
	helperH := float32(0)
	if r.ri.helperText != "" || r.ri.errText != "" {
		hs := fyne.MeasureText(r.ri.helper.Text, TextTiny, StyleBody)
		helperH = hs.Height + Sp1
	}
	inH := max(size.Height-y-helperH, 40)

	r.ri.outerBorder.Move(fyne.NewPos(0, y))
	r.ri.outerBorder.Resize(fyne.NewSize(size.Width, inH))

	r.ri.innerBG.Move(fyne.NewPos(bw, y+bw))
	r.ri.innerBG.Resize(fyne.NewSize(max(size.Width-bw*2, 0), max(inH-bw*2, 0)))

	padX := bw + 8
	padY := bw + 2
	r.innerThemed.Move(fyne.NewPos(padX, y+padY))
	r.innerThemed.Resize(fyne.NewSize(max(size.Width-padX*2, 0), max(inH-padY*2, 0)))

	dt := fyne.MeasureText(r.ri.disabledTxt.Text, TextMono, StyleMono)
	r.ri.disabledTxt.Move(fyne.NewPos(bw+12, y+(inH-dt.Height)/2))
	r.ri.disabledTxt.Resize(fyne.NewSize(max(size.Width-(bw+12)*2, 0), dt.Height))

	y += inH
	if helperH > 0 {
		r.ri.helper.Move(fyne.NewPos(0, y+Sp1))
		r.ri.helper.Resize(fyne.NewSize(size.Width, helperH-Sp1))
	}
}

func (r *inputRenderer) Refresh() {
	fill, border, _ := r.ri.FrameStyle()
	r.ri.outerBorder.FillColor = border
	r.ri.innerBG.FillColor = fill

	if r.ri.Disabled() {
		display := r.ri.Entry.Text
		if display == "" {
			display = r.ri.Entry.PlaceHolder
		} else if r.ri.inner.Password {
			display = strings.Repeat("*", len([]rune(display)))
		}
		r.ri.disabledTxt.Text = display
		r.ri.disabledTxt.Show()
		r.innerThemed.Hide()
	} else {
		r.ri.disabledTxt.Hide()
		r.innerThemed.Show()
	}

	if r.ri.errText != "" {
		r.ri.helper.Text = r.ri.errText
		r.ri.helper.Color = ColorError
	} else {
		r.ri.helper.Text = r.ri.helperText
		r.ri.helper.Color = ColorContentSecondary
	}
	r.ri.outerBorder.Refresh()
	r.ri.innerBG.Refresh()
	r.ri.disabledTxt.Refresh()
	r.ri.helper.Refresh()
	r.Layout(r.ri.Size())
}
