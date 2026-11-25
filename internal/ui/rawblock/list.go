package rawblock

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

// ListItem implements a RawBlock list row:
//   - Transparent background, Work Sans 16px text, 12px 0px item padding, no trailing icons
//   - Hover: underline text decoration
//   - Active: full-width black (#000000) background, white (#FFFFFF) text
type ListItem struct {
	widget.BaseWidget

	Text     string
	Active   bool
	OnTapped func()

	hovered bool
}

var (
	_ fyne.Tappable      = (*ListItem)(nil)
	_ desktop.Hoverable  = (*ListItem)(nil)
	_ desktop.Cursorable = (*ListItem)(nil)
)

// NewListItem creates a single text-only RawBlock list item.
func NewListItem(text string, onTapped func()) *ListItem {
	it := &ListItem{
		Text:     text,
		OnTapped: onTapped,
	}
	it.ExtendBaseWidget(it)
	return it
}

// SetActive toggles full-width black/white active inversion.
func (it *ListItem) SetActive(active bool) {
	it.Active = active
	it.Refresh()
}

// Cursor returns pointer when interactive.
func (it *ListItem) Cursor() desktop.Cursor {
	if it.OnTapped != nil {
		return desktop.PointerCursor
	}
	return desktop.DefaultCursor
}

// Tapped invokes OnTapped.
func (it *ListItem) Tapped(_ *fyne.PointEvent) {
	if it.OnTapped != nil {
		it.OnTapped()
	}
}

// MouseIn displays hover underline decoration.
func (it *ListItem) MouseIn(_ *desktop.MouseEvent) {
	it.hovered = true
	it.Refresh()
}

// MouseMoved implements desktop.Hoverable.
func (it *ListItem) MouseMoved(_ *desktop.MouseEvent) {}

// MouseOut clears hover underline decoration.
func (it *ListItem) MouseOut() {
	it.hovered = false
	it.Refresh()
}

// VisualState returns (fill, fg, underlined) for rendering and testing.
func (it *ListItem) VisualState() (fill, fg color.Color, underlined bool) {
	if it.Active {
		return ColorBlack, ColorWhite, false
	}
	return color.Transparent, ColorBlack, it.hovered
}

func (it *ListItem) CreateRenderer() fyne.WidgetRenderer {
	bg := canvas.NewRectangle(color.Transparent)
	bg.CornerRadius = RadiusNone
	lbl := NewBody(it.Text, ColorBlack)
	underline := canvas.NewRectangle(ColorBlack)
	underline.CornerRadius = RadiusNone
	underline.Hide()

	r := &listItemRenderer{
		item:      it,
		bg:        bg,
		lbl:       lbl,
		underline: underline,
		objects:   []fyne.CanvasObject{bg, lbl, underline},
	}
	r.Refresh()
	return r
}

type listItemRenderer struct {
	item      *ListItem
	bg        *canvas.Rectangle
	lbl       *canvas.Text
	underline *canvas.Rectangle
	objects   []fyne.CanvasObject
}

func (r *listItemRenderer) Destroy() {}

func (r *listItemRenderer) Objects() []fyne.CanvasObject { return r.objects }

func (r *listItemRenderer) MinSize() fyne.Size {
	ts := fyne.MeasureText(r.item.Text, TextBody, StyleBody)
	return fyne.NewSize(ts.Width+Sp2, ts.Height+24) // 12px top + 12px bottom padding
}

func (r *listItemRenderer) Layout(size fyne.Size) {
	r.bg.Move(fyne.NewPos(0, 0))
	r.bg.Resize(size)

	ts := fyne.MeasureText(r.item.Text, TextBody, StyleBody)
	xPad := float32(0)
	if r.item.Active {
		xPad = Sp2
	}
	y := (size.Height - ts.Height) / 2
	r.lbl.Move(fyne.NewPos(xPad, y))
	r.lbl.Resize(fyne.NewSize(max(size.Width-xPad, 0), ts.Height))

	r.underline.Move(fyne.NewPos(xPad, y+ts.Height+1))
	r.underline.Resize(fyne.NewSize(min(ts.Width, max(size.Width-xPad, 0)), BorderThin))
}

func (r *listItemRenderer) Refresh() {
	fill, fg, underlined := r.item.VisualState()
	r.bg.FillColor = fill
	r.lbl.Text = r.item.Text
	r.lbl.Color = fg
	r.underline.FillColor = fg
	if underlined {
		r.underline.Show()
	} else {
		r.underline.Hide()
	}
	r.bg.Refresh()
	r.lbl.Refresh()
	r.underline.Refresh()
	r.Layout(r.item.Size())
}

// List renders a RawBlock text-only vertical list separated by 3px black dividers.
type List struct {
	widget.BaseWidget

	Items      []string
	Selected   int
	OnSelected func(index int, text string)

	rows []*ListItem
}

// NewList creates a RawBlock text-only List (-1 = no active selection).
func NewList(items []string, onSelected func(index int, text string)) *List {
	l := &List{
		Items:      append([]string(nil), items...),
		Selected:   -1,
		OnSelected: onSelected,
	}
	l.ExtendBaseWidget(l)
	l.rebuildRows()
	return l
}

// SetItems replaces all items and clears active selection.
func (l *List) SetItems(items []string) {
	l.Items = append([]string(nil), items...)
	l.Selected = -1
	l.rebuildRows()
	l.Refresh()
}

// Select activates item index with full-width black fill and white text.
func (l *List) Select(index int) {
	if index < -1 || index >= len(l.Items) {
		return
	}
	l.Selected = index
	for i, row := range l.rows {
		row.SetActive(i == index)
	}
	if index >= 0 && l.OnSelected != nil {
		l.OnSelected(index, l.Items[index])
	}
}

func (l *List) rebuildRows() {
	l.rows = make([]*ListItem, len(l.Items))
	for i, text := range l.Items {
		idx := i
		item := NewListItem(text, func() {
			l.Select(idx)
		})
		item.Active = idx == l.Selected
		l.rows[i] = item
	}
}

func (l *List) CreateRenderer() fyne.WidgetRenderer {
	r := &listRenderer{list: l}
	r.syncObjects()
	return r
}

type listRenderer struct {
	list    *List
	objects []fyne.CanvasObject
}

func (r *listRenderer) Destroy() {}

func (r *listRenderer) syncObjects() {
	if len(r.list.rows) != len(r.list.Items) {
		r.list.rebuildRows()
	}
	if len(r.list.rows) == 0 {
		r.objects = nil
		return
	}
	objs := make([]fyne.CanvasObject, 0, len(r.list.rows)*2-1)
	for i, row := range r.list.rows {
		objs = append(objs, row)
		if i < len(r.list.rows)-1 {
			objs = append(objs, NewDivider(BorderThick))
		}
	}
	r.objects = objs
}

func (r *listRenderer) Objects() []fyne.CanvasObject { return r.objects }

func (r *listRenderer) MinSize() fyne.Size {
	var w, h float32
	for _, o := range r.objects {
		ms := o.MinSize()
		w = max(w, ms.Width)
		h += ms.Height
	}
	return fyne.NewSize(w, h)
}

func (r *listRenderer) Layout(size fyne.Size) {
	y := float32(0)
	for _, o := range r.objects {
		h := o.MinSize().Height
		o.Move(fyne.NewPos(0, y))
		o.Resize(fyne.NewSize(size.Width, h))
		y += h
	}
}

func (r *listRenderer) Refresh() {
	r.syncObjects()
	for _, o := range r.objects {
		o.Refresh()
	}
	r.Layout(r.list.Size())
}
