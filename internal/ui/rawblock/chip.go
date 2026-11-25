package rawblock

import (
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

// ChipTone selects a RawBlock Status Chip border and text color.
type ChipTone int

const (
	ChipDefault ChipTone = iota // #000000
	ChipActive                  // #008000
	ChipWarning                 // #FFA500
	ChipError                   // #FF0000
)

// Chip implements both RawBlock Filter Chips (2px black border, 4px/12px pad, 10px uppercase,
// 1px tracking, black/white active inversion) and Status Chips (2px colored border, 11px semibold
// uppercase, 1px tracking, 2px/10px pad).
type Chip struct {
	widget.BaseWidget

	Text     string
	Tone     ChipTone
	IsFilter bool
	Active   bool
	OnTapped func()

	hovered bool
}

var (
	_ fyne.Tappable      = (*Chip)(nil)
	_ desktop.Hoverable  = (*Chip)(nil)
	_ desktop.Cursorable = (*Chip)(nil)
)

// NewStatusChip creates a RawBlock Status Chip.
func NewStatusChip(text string, tone ChipTone) *Chip {
	c := &Chip{
		Text: strings.ToUpper(text),
		Tone: tone,
	}
	c.ExtendBaseWidget(c)
	return c
}

// NewFilterChip creates an interactive RawBlock Filter/Tab Chip.
func NewFilterChip(text string, active bool, onTapped func()) *Chip {
	c := &Chip{
		Text:     strings.ToUpper(text),
		IsFilter: true,
		Active:   active,
		OnTapped: onTapped,
	}
	c.ExtendBaseWidget(c)
	return c
}

// SetStatus updates a Status Chip's label and tone.
func (c *Chip) SetStatus(text string, tone ChipTone) {
	c.Text = strings.ToUpper(text)
	c.Tone = tone
	c.Refresh()
}

// SetActive updates a Filter Chip's active inversion state.
func (c *Chip) SetActive(active bool) {
	c.Active = active
	c.Refresh()
}

// Cursor returns pointer for filter chips and default for static status chips.
func (c *Chip) Cursor() desktop.Cursor {
	if c.IsFilter && c.OnTapped != nil {
		return desktop.PointerCursor
	}
	return desktop.DefaultCursor
}

// Tapped invokes OnTapped for filter chips.
func (c *Chip) Tapped(_ *fyne.PointEvent) {
	if c.IsFilter && c.OnTapped != nil {
		c.OnTapped()
	}
}

// MouseIn highlights filter chips on hover.
func (c *Chip) MouseIn(_ *desktop.MouseEvent) {
	if c.IsFilter {
		c.hovered = true
		c.Refresh()
	}
}

// MouseMoved implements desktop.Hoverable.
func (c *Chip) MouseMoved(_ *desktop.MouseEvent) {}

// MouseOut clears hover state.
func (c *Chip) MouseOut() {
	c.hovered = false
	c.Refresh()
}

// StyleColors returns resolved (fill, foreground, border) for rendering and verification.
func (c *Chip) StyleColors() (fill, fg, border color.Color) {
	if c.IsFilter {
		if c.Active || c.hovered {
			return ColorBlack, ColorWhite, ColorBlack
		}
		return ColorWhite, ColorBlack, ColorBlack
	}
	switch c.Tone {
	case ChipActive:
		return ColorWhite, ColorSuccess, ColorSuccess
	case ChipWarning:
		return ColorWhite, ColorWarning, ColorWarning
	case ChipError:
		return ColorWhite, ColorError, ColorError
	default:
		return ColorWhite, ColorBlack, ColorBlack
	}
}

func (c *Chip) metrics() (padV, padH, textSize float32, style fyne.TextStyle) {
	if c.IsFilter {
		return 4, 12, TextFilterChip, StyleHeadline
	}
	return 2, 10, TextStatusChip, StyleSemiBold
}

func (c *Chip) CreateRenderer() fyne.WidgetRenderer {
	outer := canvas.NewRectangle(ColorBlack)
	outer.CornerRadius = RadiusNone
	inner := canvas.NewRectangle(ColorWhite)
	inner.CornerRadius = RadiusNone
	_, _, textSize, style := c.metrics()
	lbl := NewTrackedText(c.Text, textSize, style, ColorBlack, ChipTracking)
	r := &chipRenderer{
		chip:    c,
		outer:   outer,
		inner:   inner,
		lbl:     lbl,
		objects: []fyne.CanvasObject{outer, inner, lbl},
	}
	r.Refresh()
	return r
}

type chipRenderer struct {
	chip    *Chip
	outer   *canvas.Rectangle
	inner   *canvas.Rectangle
	lbl     *TrackedText
	objects []fyne.CanvasObject
}

func (r *chipRenderer) Destroy() {}

func (r *chipRenderer) Objects() []fyne.CanvasObject { return r.objects }

func (r *chipRenderer) MinSize() fyne.Size {
	padV, padH, textSize, style := r.chip.metrics()
	r.lbl.Text = r.chip.Text
	r.lbl.TextSize = textSize
	r.lbl.TextStyle = style
	ts := r.lbl.MinSize()
	return fyne.NewSize(ts.Width+padH*2+BorderMid*2, ts.Height+padV*2+BorderMid*2)
}

func (r *chipRenderer) Layout(size fyne.Size) {
	r.outer.Move(fyne.NewPos(0, 0))
	r.outer.Resize(size)
	r.inner.Move(fyne.NewPos(BorderMid, BorderMid))
	r.inner.Resize(fyne.NewSize(max(size.Width-BorderMid*2, 0), max(size.Height-BorderMid*2, 0)))

	_, _, textSize, style := r.chip.metrics()
	r.lbl.Text = r.chip.Text
	r.lbl.TextSize = textSize
	r.lbl.TextStyle = style
	ts := r.lbl.MinSize()
	r.lbl.Move(fyne.NewPos(0, (size.Height-ts.Height)/2))
	r.lbl.Resize(fyne.NewSize(size.Width, ts.Height))
}

func (r *chipRenderer) Refresh() {
	_, _, textSize, style := r.chip.metrics()
	fill, fg, border := r.chip.StyleColors()
	r.outer.FillColor = border
	r.inner.FillColor = fill
	r.lbl.Text = r.chip.Text
	r.lbl.TextSize = textSize
	r.lbl.TextStyle = style
	r.lbl.Color = fg
	r.outer.Refresh()
	r.inner.Refresh()
	r.lbl.Refresh()
	r.Layout(r.chip.Size())
}
