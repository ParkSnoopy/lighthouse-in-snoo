package rawblock

import (
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

// ButtonVariant selects a RawBlock button treatment.
type ButtonVariant int

const (
	ButtonPrimary ButtonVariant = iota
	ButtonSecondary
	ButtonGhost
	ButtonDestructive
)

// ButtonSize selects Small (32px), Medium (44px), or Large (56px) RawBlock button dimensions.
type ButtonSize int

const (
	ButtonSmall ButtonSize = iota
	ButtonMedium
	ButtonLarge
)

// Button implements RawBlock Primary, Secondary, Ghost, and Destructive buttons
// with uppercase 2px tracking, full color inversion on hover, 5px active border,
// square corners (0px radius), and non-opacity disabled styling.
type Button struct {
	widget.BaseWidget

	Text     string
	Variant  ButtonVariant
	BtnSize  ButtonSize
	OnTapped func()

	hovered  bool
	pressed  bool
	disabled bool
}

var (
	_ fyne.Tappable      = (*Button)(nil)
	_ fyne.Disableable   = (*Button)(nil)
	_ desktop.Hoverable  = (*Button)(nil)
	_ desktop.Mouseable  = (*Button)(nil)
	_ desktop.Cursorable = (*Button)(nil)
)

// NewButton creates a RawBlock square button.
func NewButton(label string, variant ButtonVariant, size ButtonSize, onTapped func()) *Button {
	b := &Button{
		Text:     strings.ToUpper(label),
		Variant:  variant,
		BtnSize:  size,
		OnTapped: onTapped,
	}
	b.ExtendBaseWidget(b)
	return b
}

// SetText updates the uppercased button text.
func (b *Button) SetText(label string) {
	b.Text = strings.ToUpper(label)
	b.Refresh()
}

// SetVariant switches button treatment dynamically.
func (b *Button) SetVariant(v ButtonVariant) {
	b.Variant = v
	b.Refresh()
}

// Disable applies RawBlock disabled surface (#F0F0F0), tertiary text, and 3px #CCCCCC border.
func (b *Button) Disable() {
	b.disabled = true
	b.hovered = false
	b.pressed = false
	b.Refresh()
}

// Enable restores interactive styling.
func (b *Button) Enable() {
	b.disabled = false
	b.Refresh()
}

// Disabled reports whether the button is disabled.
func (b *Button) Disabled() bool { return b.disabled }

// Cursor returns pointer when enabled and default cursor when disabled.
func (b *Button) Cursor() desktop.Cursor {
	if b.disabled {
		return desktop.DefaultCursor
	}
	return desktop.PointerCursor
}

// Tapped invokes OnTapped when enabled.
func (b *Button) Tapped(_ *fyne.PointEvent) {
	if b.disabled || b.OnTapped == nil {
		return
	}
	b.OnTapped()
}

// MouseIn activates RawBlock hover inversion.
func (b *Button) MouseIn(_ *desktop.MouseEvent) {
	if b.disabled {
		return
	}
	b.hovered = true
	b.Refresh()
}

// MouseMoved implements desktop.Hoverable.
func (b *Button) MouseMoved(_ *desktop.MouseEvent) {}

// MouseOut clears hover state.
func (b *Button) MouseOut() {
	b.hovered = false
	b.pressed = false
	b.Refresh()
}

// MouseDown engages RawBlock active state (5px border).
func (b *Button) MouseDown(_ *desktop.MouseEvent) {
	if b.disabled {
		return
	}
	b.pressed = true
	b.Refresh()
}

// MouseUp releases active state.
func (b *Button) MouseUp(_ *desktop.MouseEvent) {
	b.pressed = false
	b.Refresh()
}

func (b *Button) metrics() (padV, padH, textSize, minH float32) {
	switch b.BtnSize {
	case ButtonSmall:
		return 6, 16, TextMin, 34
	case ButtonLarge:
		return 16, 40, 18, 56
	default:
		return 10, 24, TextMin, 44
	}
}

// TextSize returns the button's resolved font size (always >= TextMin).
func (b *Button) TextSize() float32 {
	_, _, textSize, _ := b.metrics()
	return textSize
}

// StyleColors returns the current resolved (fill, foreground, border, borderWidth) for rendering and verification.
func (b *Button) StyleColors() (fill, fg, stroke color.Color, borderW float32) {
	switch {
	case b.disabled:
		if b.Variant == ButtonGhost {
			return color.Transparent, ColorContentTertiary, color.Transparent, 0
		}
		return ColorSurfaceSunken, ColorContentTertiary, ColorBorderDisabled, BorderThick

	case b.Variant == ButtonPrimary:
		switch {
		case b.pressed:
			return ColorBlack, ColorWhite, ColorBlack, BorderHeavy
		case b.hovered:
			return ColorWhite, ColorBlack, ColorBlack, BorderThick
		default:
			return ColorBlack, ColorWhite, ColorBlack, BorderThick
		}

	case b.Variant == ButtonSecondary:
		switch {
		case b.pressed:
			return ColorBlack, ColorWhite, ColorBlack, BorderHeavy
		case b.hovered:
			return ColorBlack, ColorWhite, ColorBlack, BorderThick
		default:
			return ColorWhite, ColorBlack, ColorBlack, BorderThick
		}

	case b.Variant == ButtonGhost:
		if b.hovered || b.pressed {
			return color.Transparent, ColorBlue, color.Transparent, 0
		}
		return color.Transparent, ColorBlack, color.Transparent, 0

	case b.Variant == ButtonDestructive:
		switch {
		case b.pressed:
			return ColorBlack, ColorError, ColorBlack, BorderHeavy
		case b.hovered:
			return ColorBlack, ColorError, ColorBlack, BorderThick
		default:
			return ColorError, ColorWhite, ColorBlack, BorderThick
		}

	default:
		return ColorBlack, ColorWhite, ColorBlack, BorderThick
	}
}

func (b *Button) CreateRenderer() fyne.WidgetRenderer {
	outer := canvas.NewRectangle(ColorBlack)
	outer.CornerRadius = RadiusNone
	inner := canvas.NewRectangle(ColorBlack)
	inner.CornerRadius = RadiusNone
	_, _, textSize, _ := b.metrics()
	lbl := NewTrackedText(b.Text, textSize, StyleHeadline, ColorWhite, ButtonTracking)
	underline := canvas.NewRectangle(ColorBlack)
	underline.CornerRadius = RadiusNone

	r := &buttonRenderer{
		btn:       b,
		outer:     outer,
		inner:     inner,
		lbl:       lbl,
		underline: underline,
		objects:   []fyne.CanvasObject{outer, inner, lbl, underline},
	}
	r.Refresh()
	return r
}

type buttonRenderer struct {
	btn       *Button
	outer     *canvas.Rectangle
	inner     *canvas.Rectangle
	lbl       *TrackedText
	underline *canvas.Rectangle
	objects   []fyne.CanvasObject
}

func (r *buttonRenderer) Destroy() {}

func (r *buttonRenderer) Objects() []fyne.CanvasObject { return r.objects }

func (r *buttonRenderer) MinSize() fyne.Size {
	padV, padH, textSize, minH := r.btn.metrics()
	r.lbl.Text = r.btn.Text
	r.lbl.TextSize = textSize
	ts := r.lbl.MinSize()
	w := ts.Width + padH*2 + BorderHeavy*2
	h := max(ts.Height+padV*2, minH)
	return fyne.NewSize(w, h)
}

func (r *buttonRenderer) Layout(size fyne.Size) {
	_, _, _, sw := r.btn.StyleColors()
	r.outer.Move(fyne.NewPos(0, 0))
	r.outer.Resize(size)

	r.inner.Move(fyne.NewPos(sw, sw))
	r.inner.Resize(fyne.NewSize(max(size.Width-sw*2, 0), max(size.Height-sw*2, 0)))

	_, _, textSize, _ := r.btn.metrics()
	r.lbl.Text = r.btn.Text
	r.lbl.TextSize = textSize
	ts := r.lbl.MinSize()
	r.lbl.Move(fyne.NewPos(0, (size.Height-ts.Height)/2))
	r.lbl.Resize(fyne.NewSize(size.Width, ts.Height))

	if r.btn.Variant == ButtonGhost {
		ulW := min(ts.Width, size.Width)
		ulX := (size.Width - ulW) / 2
		ulY := (size.Height+ts.Height)/2 + 2
		r.underline.Move(fyne.NewPos(ulX, ulY))
		r.underline.Resize(fyne.NewSize(ulW, BorderThin))
		r.underline.Show()
	} else {
		r.underline.Hide()
	}
}

func (r *buttonRenderer) Refresh() {
	_, _, textSize, _ := r.btn.metrics()
	fill, fg, stroke, sw := r.btn.StyleColors()

	if sw <= 0 {
		r.outer.FillColor = color.Transparent
	} else {
		r.outer.FillColor = stroke
	}
	r.inner.FillColor = fill
	r.lbl.Text = r.btn.Text
	r.lbl.TextSize = textSize
	r.lbl.Color = fg
	r.underline.FillColor = fg

	r.outer.Refresh()
	r.inner.Refresh()
	r.lbl.Refresh()
	r.underline.Refresh()
	r.Layout(r.btn.Size())
}
