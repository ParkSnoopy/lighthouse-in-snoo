package rawblock

import (
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

// RadioOption implements a single RawBlock Radio Button:
//   - 20px x 20px circle (the one intentional exception to 0px radius)
//   - 3px black border; white unchecked fill; selected: 10px black inner dot
//   - Focus: 5px black border; Disabled: #CCCCCC border, #F5F5F5 fill
type RadioOption struct {
	widget.BaseWidget

	Label      string
	Selected   bool
	OnSelected func()

	focused  bool
	hovered  bool
	disabled bool
}

var (
	_ fyne.Tappable      = (*RadioOption)(nil)
	_ fyne.Focusable     = (*RadioOption)(nil)
	_ fyne.Disableable   = (*RadioOption)(nil)
	_ desktop.Hoverable  = (*RadioOption)(nil)
	_ desktop.Cursorable = (*RadioOption)(nil)
)

// NewRadioOption creates a single RawBlock circular radio option.
func NewRadioOption(label string, selected bool, onSelected func()) *RadioOption {
	ro := &RadioOption{
		Label:      strings.ToUpper(label),
		Selected:   selected,
		OnSelected: onSelected,
	}
	ro.ExtendBaseWidget(ro)
	return ro
}

// SetSelected updates selection state.
func (r *RadioOption) SetSelected(sel bool) {
	r.Selected = sel
	r.Refresh()
}

// Disable applies #CCCCCC border and #F5F5F5 fill.
func (r *RadioOption) Disable() {
	r.disabled = true
	r.hovered = false
	r.focused = false
	r.Refresh()
}

// Enable restores interactive state.
func (r *RadioOption) Enable() {
	r.disabled = false
	r.Refresh()
}

// Disabled reports whether the option is disabled.
func (r *RadioOption) Disabled() bool { return r.disabled }

// Cursor returns pointer when enabled.
func (r *RadioOption) Cursor() desktop.Cursor {
	if r.disabled {
		return desktop.DefaultCursor
	}
	return desktop.PointerCursor
}

// Tapped selects this option.
func (r *RadioOption) Tapped(_ *fyne.PointEvent) {
	if r.disabled || r.OnSelected == nil {
		return
	}
	r.OnSelected()
}

// FocusGained sets 5px focus border.
func (r *RadioOption) FocusGained() {
	r.focused = true
	r.Refresh()
}

// FocusLost restores 3px border.
func (r *RadioOption) FocusLost() {
	r.focused = false
	r.Refresh()
}

// TypedRune selects on Space.
func (r *RadioOption) TypedRune(ch rune) {
	if !r.disabled && ch == ' ' && r.OnSelected != nil {
		r.OnSelected()
	}
}

// TypedKey selects on Space or Return.
func (r *RadioOption) TypedKey(ev *fyne.KeyEvent) {
	if !r.disabled && (ev.Name == fyne.KeySpace || ev.Name == fyne.KeyReturn) && r.OnSelected != nil {
		r.OnSelected()
	}
}

// MouseIn sets hover state.
func (r *RadioOption) MouseIn(_ *desktop.MouseEvent) {
	if !r.disabled {
		r.hovered = true
		r.Refresh()
	}
}

// MouseMoved implements desktop.Hoverable.
func (r *RadioOption) MouseMoved(_ *desktop.MouseEvent) {}

// MouseOut clears hover state.
func (r *RadioOption) MouseOut() {
	r.hovered = false
	r.Refresh()
}

// CircleStyle returns (outerFill, borderColor, dotColor, borderWidth) for rendering and verification.
func (r *RadioOption) CircleStyle() (fill, border, dot color.Color, borderW float32) {
	if r.disabled {
		return ColorSurfaceDisabled, ColorBorderDisabled, ColorBorderDisabled, BorderThick
	}
	bw := BorderThick
	if r.focused {
		bw = BorderHeavy
	}
	if r.hovered && !r.Selected {
		return ColorSurfaceHover, ColorBlack, ColorBlack, bw
	}
	return ColorWhite, ColorBlack, ColorBlack, bw
}

func (r *RadioOption) CreateRenderer() fyne.WidgetRenderer {
	outer := canvas.NewCircle(ColorWhite)
	outer.StrokeColor = ColorBlack
	outer.StrokeWidth = BorderThick
	dot := canvas.NewCircle(ColorBlack)
	lbl := NewLabel(r.Label, ColorBlack)

	ren := &radioOptionRenderer{
		opt:     r,
		outer:   outer,
		dot:     dot,
		lbl:     lbl,
		objects: []fyne.CanvasObject{outer, dot, lbl},
	}
	ren.Refresh()
	return ren
}

type radioOptionRenderer struct {
	opt     *RadioOption
	outer   *canvas.Circle
	dot     *canvas.Circle
	lbl     *canvas.Text
	objects []fyne.CanvasObject
}

func (r *radioOptionRenderer) Destroy() {}

func (r *radioOptionRenderer) Objects() []fyne.CanvasObject { return r.objects }

func (r *radioOptionRenderer) MinSize() fyne.Size {
	ts := fyne.MeasureText(r.opt.Label, TextSmall, StyleHeadline)
	w := float32(20) + 12 + ts.Width + Sp1
	h := max(float32(28), ts.Height+Sp2)
	return fyne.NewSize(w, h)
}

func (r *radioOptionRenderer) Layout(size fyne.Size) {
	const outerDim float32 = 20
	const dotDim float32 = 10

	outerY := (size.Height - outerDim) / 2
	r.outer.Move(fyne.NewPos(0, outerY))
	r.outer.Resize(fyne.NewSize(outerDim, outerDim))

	dotOffset := (outerDim - dotDim) / 2
	r.dot.Move(fyne.NewPos(dotOffset, outerY+dotOffset))
	r.dot.Resize(fyne.NewSize(dotDim, dotDim))

	ts := fyne.MeasureText(r.opt.Label, TextSmall, StyleHeadline)
	r.lbl.Move(fyne.NewPos(outerDim+12, (size.Height-ts.Height)/2))
	r.lbl.Resize(fyne.NewSize(max(ts.Width, size.Width-outerDim-12), ts.Height))
}

func (r *radioOptionRenderer) Refresh() {
	fill, border, dotCol, bw := r.opt.CircleStyle()
	r.outer.FillColor = fill
	r.outer.StrokeColor = border
	r.outer.StrokeWidth = bw
	r.dot.FillColor = dotCol
	if r.opt.Selected {
		r.dot.Show()
	} else {
		r.dot.Hide()
	}
	r.lbl.Text = r.opt.Label
	if r.opt.disabled {
		r.lbl.Color = ColorContentTertiary
	} else {
		r.lbl.Color = ColorBlack
	}
	r.outer.Refresh()
	r.dot.Refresh()
	r.lbl.Refresh()
}

// RadioGroup coordinates a mutually exclusive set of RawBlock circular RadioOptions.
type RadioGroup struct {
	widget.BaseWidget

	Options    []string
	Selected   string
	Horizontal bool
	OnChanged  func(string)

	items    []*RadioOption
	disabled bool
}

var _ fyne.Disableable = (*RadioGroup)(nil)

// NewRadioGroup constructs a RawBlock radio group.
func NewRadioGroup(options []string, selected string, onChanged func(string)) *RadioGroup {
	rg := &RadioGroup{
		Options:   append([]string(nil), options...),
		Selected:  selected,
		OnChanged: onChanged,
	}
	rg.ExtendBaseWidget(rg)
	rg.rebuildItems()
	return rg
}

// SetSelected selects option value and triggers OnChanged if changed.
func (g *RadioGroup) SetSelected(value string) {
	if g.Selected == value {
		return
	}
	g.Selected = value
	for i, opt := range g.Options {
		if i < len(g.items) {
			g.items[i].SetSelected(opt == value)
		}
	}
	if g.OnChanged != nil {
		g.OnChanged(value)
	}
}

// Disable disables every radio option in the group.
func (g *RadioGroup) Disable() {
	g.disabled = true
	for _, it := range g.items {
		it.Disable()
	}
}

// Enable re-enables every radio option in the group.
func (g *RadioGroup) Enable() {
	g.disabled = false
	for _, it := range g.items {
		it.Enable()
	}
}

// Disabled reports whether the group is disabled.
func (g *RadioGroup) Disabled() bool { return g.disabled }

func (g *RadioGroup) rebuildItems() {
	g.items = make([]*RadioOption, len(g.Options))
	for i, opt := range g.Options {
		val := opt
		it := NewRadioOption(val, val == g.Selected, func() {
			g.SetSelected(val)
		})
		if g.disabled {
			it.Disable()
		}
		g.items[i] = it
	}
}

func (g *RadioGroup) CreateRenderer() fyne.WidgetRenderer {
	if len(g.items) != len(g.Options) {
		g.rebuildItems()
	}
	objs := make([]fyne.CanvasObject, len(g.items))
	for i, it := range g.items {
		objs[i] = it
	}
	return &radioGroupRenderer{group: g, objects: objs}
}

type radioGroupRenderer struct {
	group   *RadioGroup
	objects []fyne.CanvasObject
}

func (r *radioGroupRenderer) Destroy() {}

func (r *radioGroupRenderer) Objects() []fyne.CanvasObject { return r.objects }

func (r *radioGroupRenderer) MinSize() fyne.Size {
	var w, h float32
	for i, o := range r.objects {
		ms := o.MinSize()
		if r.group.Horizontal {
			w += ms.Width
			if i > 0 {
				w += Sp3
			}
			h = max(h, ms.Height)
		} else {
			w = max(w, ms.Width)
			h += ms.Height
			if i > 0 {
				h += Sp2
			}
		}
	}
	return fyne.NewSize(w, h)
}

func (r *radioGroupRenderer) Layout(size fyne.Size) {
	var pos float32
	for _, o := range r.objects {
		ms := o.MinSize()
		if r.group.Horizontal {
			o.Move(fyne.NewPos(pos, (size.Height-ms.Height)/2))
			o.Resize(ms)
			pos += ms.Width + Sp3
		} else {
			o.Move(fyne.NewPos(0, pos))
			o.Resize(fyne.NewSize(size.Width, ms.Height))
			pos += ms.Height + Sp2
		}
	}
}

func (r *radioGroupRenderer) Refresh() {
	for i, opt := range r.group.Options {
		if i < len(r.group.items) {
			r.group.items[i].SetSelected(opt == r.group.Selected)
		}
	}
	r.Layout(r.group.Size())
}
