package rawblock

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"
)

// CardStyle selects RawBlock Card hierarchy via border weight or full black inversion (zero shadows).
type CardStyle int

const (
	CardDefault  CardStyle = iota // White fill, 3px black border, sp-4 (24px) padding
	CardElevated                  // White fill, 5px black border, sp-4 (24px) padding
	CardInverted                  // Black fill, 3px black border, sp-4 (24px) padding
)

// Card implements RawBlock's zero-radius, zero-shadow bordered container.
type Card struct {
	widget.BaseWidget

	Content fyne.CanvasObject
	Style   CardStyle
	Padding float32
}

// NewCard creates a RawBlock Card with sp-4 (24px) default padding.
func NewCard(content fyne.CanvasObject, style CardStyle) *Card {
	c := &Card{
		Content: content,
		Style:   style,
		Padding: Sp4,
	}
	c.ExtendBaseWidget(c)
	return c
}

// NewCardWithPadding creates a RawBlock Card with an explicit RawBlock spacing token.
func NewCardWithPadding(content fyne.CanvasObject, style CardStyle, pad float32) *Card {
	c := &Card{
		Content: content,
		Style:   style,
		Padding: pad,
	}
	c.ExtendBaseWidget(c)
	return c
}

// SetStyle updates the card border weight / surface inversion.
func (c *Card) SetStyle(style CardStyle) {
	c.Style = style
	c.Refresh()
}

// StyleSpec returns (fill, borderColor, borderWidth) for rendering and tests.
func (c *Card) StyleSpec() (fill, border color.Color, borderW float32) {
	switch c.Style {
	case CardElevated:
		return ColorWhite, ColorBlack, BorderHeavy
	case CardInverted:
		return ColorBlack, ColorBlack, BorderThick
	default:
		return ColorWhite, ColorBlack, BorderThick
	}
}

func (c *Card) CreateRenderer() fyne.WidgetRenderer {
	outer := canvas.NewRectangle(ColorBlack)
	outer.CornerRadius = RadiusNone
	inner := canvas.NewRectangle(ColorWhite)
	inner.CornerRadius = RadiusNone
	objs := []fyne.CanvasObject{outer, inner}
	if c.Content != nil {
		objs = append(objs, c.Content)
	}
	r := &cardRenderer{
		card:    c,
		outer:   outer,
		inner:   inner,
		objects: objs,
	}
	r.Refresh()
	return r
}

type cardRenderer struct {
	card    *Card
	outer   *canvas.Rectangle
	inner   *canvas.Rectangle
	objects []fyne.CanvasObject
}

func (r *cardRenderer) Destroy() {}

func (r *cardRenderer) Objects() []fyne.CanvasObject { return r.objects }

func (r *cardRenderer) MinSize() fyne.Size {
	_, _, bw := r.card.StyleSpec()
	pad := r.card.Padding + bw
	if r.card.Content == nil {
		return fyne.NewSize(pad*2, pad*2)
	}
	ms := r.card.Content.MinSize()
	return fyne.NewSize(ms.Width+pad*2, ms.Height+pad*2)
}

func (r *cardRenderer) Layout(size fyne.Size) {
	_, _, bw := r.card.StyleSpec()
	r.outer.Move(fyne.NewPos(0, 0))
	r.outer.Resize(size)
	r.inner.Move(fyne.NewPos(bw, bw))
	r.inner.Resize(fyne.NewSize(max(size.Width-bw*2, 0), max(size.Height-bw*2, 0)))

	if r.card.Content != nil {
		inset := r.card.Padding + bw
		r.card.Content.Move(fyne.NewPos(inset, inset))
		r.card.Content.Resize(fyne.NewSize(max(size.Width-inset*2, 0), max(size.Height-inset*2, 0)))
	}
}

func (r *cardRenderer) Refresh() {
	fill, border, _ := r.card.StyleSpec()
	r.outer.FillColor = border
	r.inner.FillColor = fill
	r.outer.Refresh()
	r.inner.Refresh()
	r.Layout(r.card.Size())
}
