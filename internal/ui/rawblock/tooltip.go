package rawblock

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

const tooltipMaxWidth float32 = 260

// Tooltip implements RawBlock's inverted tooltip block:
//   - Black (#000000) fill, white (#FFFFFF) 14px Space Mono text
//   - Square (0px radius), no border, no shadow, no arrow
//   - 8px/12px padding, 260px max width
type Tooltip struct {
	widget.BaseWidget

	Text string
}

// NewTooltip creates a standalone RawBlock Tooltip block.
func NewTooltip(text string) *Tooltip {
	t := &Tooltip{Text: text}
	t.ExtendBaseWidget(t)
	return t
}

func (t *Tooltip) CreateRenderer() fyne.WidgetRenderer {
	bg := canvas.NewRectangle(ColorBlack)
	bg.CornerRadius = RadiusNone
	lines := wrapMonoLines(t.Text, tooltipMaxWidth-24)
	r := &tooltipRenderer{
		tip:   t,
		bg:    bg,
		lines: lines,
	}
	r.syncObjects()
	return r
}

func wrapMonoLines(text string, maxContentW float32) []*canvas.Text {
	words := strings.Fields(text)
	if len(words) == 0 {
		t := canvas.NewText("", ColorWhite)
		t.TextSize = TextTooltip
		t.TextStyle = StyleMono
		return []*canvas.Text{t}
	}
	var out []*canvas.Text
	cur := words[0]
	for _, w := range words[1:] {
		cand := cur + " " + w
		if fyne.MeasureText(cand, TextTooltip, StyleMono).Width <= maxContentW {
			cur = cand
		} else {
			t := canvas.NewText(cur, ColorWhite)
			t.TextSize = TextTooltip
			t.TextStyle = StyleMono
			out = append(out, t)
			cur = w
		}
	}
	t := canvas.NewText(cur, ColorWhite)
	t.TextSize = TextTooltip
	t.TextStyle = StyleMono
	out = append(out, t)
	return out
}

type tooltipRenderer struct {
	tip     *Tooltip
	bg      *canvas.Rectangle
	lines   []*canvas.Text
	objects []fyne.CanvasObject
}

func (r *tooltipRenderer) Destroy() {}

func (r *tooltipRenderer) syncObjects() {
	r.objects = make([]fyne.CanvasObject, 0, len(r.lines)+1)
	r.objects = append(r.objects, r.bg)
	for _, l := range r.lines {
		r.objects = append(r.objects, l)
	}
}

func (r *tooltipRenderer) Objects() []fyne.CanvasObject { return r.objects }

func (r *tooltipRenderer) MinSize() fyne.Size {
	var maxW, totalH float32
	for i, l := range r.lines {
		ms := fyne.MeasureText(l.Text, TextTooltip, StyleMono)
		maxW = max(maxW, ms.Width)
		totalH += ms.Height
		if i > 0 {
			totalH += Sp1
		}
	}
	w := min(maxW+24, tooltipMaxWidth) // 12px left + 12px right padding
	h := totalH + 16                   // 8px top + 8px bottom padding
	return fyne.NewSize(w, h)
}

func (r *tooltipRenderer) Layout(size fyne.Size) {
	r.bg.Move(fyne.NewPos(0, 0))
	r.bg.Resize(size)
	y := float32(8)
	for _, l := range r.lines {
		ms := fyne.MeasureText(l.Text, TextTooltip, StyleMono)
		l.Move(fyne.NewPos(12, y))
		l.Resize(fyne.NewSize(max(size.Width-24, 0), ms.Height))
		y += ms.Height + Sp1
	}
}

func (r *tooltipRenderer) Refresh() {
	r.lines = wrapMonoLines(r.tip.Text, tooltipMaxWidth-24)
	r.syncObjects()
	r.bg.FillColor = ColorBlack
	r.bg.Refresh()
	r.Layout(r.tip.Size())
}

// TooltipWrap attaches a directly-adjacent, arrow-free RawBlock Tooltip on hover.
type TooltipWrap struct {
	widget.BaseWidget

	Content fyne.CanvasObject
	Tip     string

	popup *widget.PopUp
}

var _ desktop.Hoverable = (*TooltipWrap)(nil)

// WithTooltip wraps content so hovering shows an adjacent inverted RawBlock Tooltip.
func WithTooltip(content fyne.CanvasObject, tip string) *TooltipWrap {
	tw := &TooltipWrap{
		Content: content,
		Tip:     tip,
	}
	tw.ExtendBaseWidget(tw)
	return tw
}

// MouseIn displays the tooltip directly adjacent below the wrapped object (no arrow).
func (tw *TooltipWrap) MouseIn(_ *desktop.MouseEvent) {
	if tw.Tip == "" || tw.popup != nil {
		return
	}
	app := fyne.CurrentApp()
	if app == nil || app.Driver() == nil {
		return
	}
	cv := app.Driver().CanvasForObject(tw)
	if cv == nil {
		return
	}
	pos := app.Driver().AbsolutePositionForObject(tw)
	tipObj := NewTooltip(tw.Tip)
	pop := widget.NewPopUp(tipObj, cv)
	pop.ShowAtPosition(fyne.NewPos(pos.X, pos.Y+tw.Size().Height))
	tw.popup = pop
}

// MouseMoved implements desktop.Hoverable.
func (tw *TooltipWrap) MouseMoved(_ *desktop.MouseEvent) {}

// MouseOut hides the active tooltip popup.
func (tw *TooltipWrap) MouseOut() {
	if tw.popup != nil {
		tw.popup.Hide()
		tw.popup = nil
	}
}

// Showing reports whether the tooltip popup is currently active.
func (tw *TooltipWrap) Showing() bool { return tw.popup != nil }

func (tw *TooltipWrap) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(tw.Content)
}
