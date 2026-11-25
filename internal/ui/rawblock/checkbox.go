package rawblock

import (
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

// Check implements RawBlock's 20x20 square 3px-bordered checkbox with a 3px white stroke checkmark,
// 5px focus border, and #CCCCCC/#F5F5F5 disabled state.
type Check struct {
	widget.BaseWidget

	Text      string
	Checked   bool
	OnChanged func(bool)

	focused  bool
	hovered  bool
	disabled bool
}

var (
	_ fyne.Tappable      = (*Check)(nil)
	_ fyne.Focusable     = (*Check)(nil)
	_ fyne.Disableable   = (*Check)(nil)
	_ desktop.Hoverable  = (*Check)(nil)
	_ desktop.Cursorable = (*Check)(nil)
)

// NewCheck creates a RawBlock checkbox.
func NewCheck(label string, onChanged func(bool)) *Check {
	c := &Check{
		Text:      strings.ToUpper(label),
		OnChanged: onChanged,
	}
	c.ExtendBaseWidget(c)
	return c
}

// SetChecked updates Checked and invokes OnChanged when toggled.
func (c *Check) SetChecked(checked bool) {
	if c.Checked == checked {
		return
	}
	c.Checked = checked
	c.Refresh()
	if c.OnChanged != nil {
		c.OnChanged(checked)
	}
}

// SetCheckedSilent updates Checked without triggering OnChanged.
func (c *Check) SetCheckedSilent(checked bool) {
	c.Checked = checked
	c.Refresh()
}

// Disable applies #CCCCCC border and #F5F5F5 fill.
func (c *Check) Disable() {
	c.disabled = true
	c.hovered = false
	c.focused = false
	c.Refresh()
}

// Enable restores interactive state.
func (c *Check) Enable() {
	c.disabled = false
	c.Refresh()
}

// Disabled reports whether the checkbox is disabled.
func (c *Check) Disabled() bool { return c.disabled }

// Cursor returns pointer when enabled.
func (c *Check) Cursor() desktop.Cursor {
	if c.disabled {
		return desktop.DefaultCursor
	}
	return desktop.PointerCursor
}

// Tapped toggles Checked.
func (c *Check) Tapped(_ *fyne.PointEvent) {
	if c.disabled {
		return
	}
	c.SetChecked(!c.Checked)
}

// FocusGained activates 5px focus border.
func (c *Check) FocusGained() {
	c.focused = true
	c.Refresh()
}

// FocusLost restores 3px border.
func (c *Check) FocusLost() {
	c.focused = false
	c.Refresh()
}

// TypedRune toggles on Space.
func (c *Check) TypedRune(r rune) {
	if !c.disabled && r == ' ' {
		c.SetChecked(!c.Checked)
	}
}

// TypedKey toggles on Space or Return.
func (c *Check) TypedKey(ev *fyne.KeyEvent) {
	if !c.disabled && (ev.Name == fyne.KeySpace || ev.Name == fyne.KeyReturn) {
		c.SetChecked(!c.Checked)
	}
}

// MouseIn highlights unchecked hover surface.
func (c *Check) MouseIn(_ *desktop.MouseEvent) {
	if !c.disabled {
		c.hovered = true
		c.Refresh()
	}
}

// MouseMoved implements desktop.Hoverable.
func (c *Check) MouseMoved(_ *desktop.MouseEvent) {}

// MouseOut clears hover state.
func (c *Check) MouseOut() {
	c.hovered = false
	c.Refresh()
}

// BoxStyle returns (fill, borderColor, borderWidth) for rendering and testing.
func (c *Check) BoxStyle() (fill, border color.Color, borderW float32) {
	if c.disabled {
		return ColorSurfaceDisabled, ColorBorderDisabled, BorderThick
	}
	bw := BorderThick
	if c.focused {
		bw = BorderHeavy
	}
	if c.Checked {
		return ColorBlack, ColorBlack, bw
	}
	if c.hovered {
		return ColorSurfaceHover, ColorBlack, bw
	}
	return ColorWhite, ColorBlack, bw
}

func (c *Check) CreateRenderer() fyne.WidgetRenderer {
	outer := canvas.NewRectangle(ColorBlack)
	outer.CornerRadius = RadiusNone
	inner := canvas.NewRectangle(ColorWhite)
	inner.CornerRadius = RadiusNone
	check1 := canvas.NewLine(ColorWhite)
	check1.StrokeWidth = BorderThick
	check2 := canvas.NewLine(ColorWhite)
	check2.StrokeWidth = BorderThick
	lbl := NewLabel(c.Text, ColorBlack)

	r := &checkRenderer{
		chk:     c,
		outer:   outer,
		inner:   inner,
		check1:  check1,
		check2:  check2,
		lbl:     lbl,
		objects: []fyne.CanvasObject{outer, inner, check1, check2, lbl},
	}
	r.Refresh()
	return r
}

type checkRenderer struct {
	chk     *Check
	outer   *canvas.Rectangle
	inner   *canvas.Rectangle
	check1  *canvas.Line
	check2  *canvas.Line
	lbl     *canvas.Text
	objects []fyne.CanvasObject
}

func (r *checkRenderer) Destroy() {}

func (r *checkRenderer) Objects() []fyne.CanvasObject { return r.objects }

func (r *checkRenderer) MinSize() fyne.Size {
	ts := fyne.MeasureText(r.chk.Text, TextSmall, StyleHeadline)
	w := float32(20) + 12 + ts.Width + Sp1
	h := max(float32(28), ts.Height+Sp2)
	return fyne.NewSize(w, h)
}

func (r *checkRenderer) Layout(size fyne.Size) {
	const boxDim float32 = 20
	_, _, bw := r.chk.BoxStyle()
	boxY := (size.Height - boxDim) / 2
	r.outer.Move(fyne.NewPos(0, boxY))
	r.outer.Resize(fyne.NewSize(boxDim, boxDim))
	r.inner.Move(fyne.NewPos(bw, boxY+bw))
	r.inner.Resize(fyne.NewSize(max(boxDim-bw*2, 0), max(boxDim-bw*2, 0)))

	r.check1.Position1 = fyne.NewPos(4, boxY+10)
	r.check1.Position2 = fyne.NewPos(8.5, boxY+14.5)
	r.check2.Position1 = fyne.NewPos(8, boxY+14.5)
	r.check2.Position2 = fyne.NewPos(16, boxY+5.5)

	ts := fyne.MeasureText(r.chk.Text, TextSmall, StyleHeadline)
	r.lbl.Move(fyne.NewPos(boxDim+12, (size.Height-ts.Height)/2))
	r.lbl.Resize(fyne.NewSize(max(ts.Width, size.Width-boxDim-12), ts.Height))
}

func (r *checkRenderer) Refresh() {
	fill, border, _ := r.chk.BoxStyle()
	r.outer.FillColor = border
	r.inner.FillColor = fill

	r.lbl.Text = r.chk.Text
	if r.chk.disabled {
		r.lbl.Color = ColorContentTertiary
		r.check1.StrokeColor = ColorBorderDisabled
		r.check2.StrokeColor = ColorBorderDisabled
	} else {
		r.lbl.Color = ColorBlack
		r.check1.StrokeColor = ColorWhite
		r.check2.StrokeColor = ColorWhite
	}

	if r.chk.Checked {
		r.check1.Show()
		r.check2.Show()
	} else {
		r.check1.Hide()
		r.check2.Hide()
	}
	r.outer.Refresh()
	r.inner.Refresh()
	r.check1.Refresh()
	r.check2.Refresh()
	r.lbl.Refresh()
	r.Layout(r.chk.Size())
}
