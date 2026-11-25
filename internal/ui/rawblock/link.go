package rawblock

import (
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

// Link implements RawBlock's hyperlink primitive — the ONLY component permitted to use #0000FF blue.
type Link struct {
	widget.BaseWidget

	Text     string
	URL      *url.URL
	OnTapped func()
}

var (
	_ fyne.Tappable      = (*Link)(nil)
	_ desktop.Cursorable = (*Link)(nil)
)

// NewLink creates a RawBlock blue (#0000FF) underlined hyperlink.
func NewLink(text string, u *url.URL, onTapped func()) *Link {
	l := &Link{
		Text:     text,
		URL:      u,
		OnTapped: onTapped,
	}
	l.ExtendBaseWidget(l)
	return l
}

// Cursor returns pointer cursor.
func (l *Link) Cursor() desktop.Cursor { return desktop.PointerCursor }

// Tapped invokes OnTapped or opens URL via Fyne app.
func (l *Link) Tapped(_ *fyne.PointEvent) {
	if l.OnTapped != nil {
		l.OnTapped()
		return
	}
	if l.URL != nil {
		if app := fyne.CurrentApp(); app != nil {
			_ = app.OpenURL(l.URL)
		}
	}
}

func (l *Link) CreateRenderer() fyne.WidgetRenderer {
	txt := NewBody(l.Text, ColorBlue)
	ul := canvas.NewRectangle(ColorBlue)
	ul.CornerRadius = RadiusNone
	return &linkRenderer{
		link:    l,
		txt:     txt,
		ul:      ul,
		objects: []fyne.CanvasObject{txt, ul},
	}
}

type linkRenderer struct {
	link    *Link
	txt     *canvas.Text
	ul      *canvas.Rectangle
	objects []fyne.CanvasObject
}

func (r *linkRenderer) Destroy() {}

func (r *linkRenderer) Objects() []fyne.CanvasObject { return r.objects }

func (r *linkRenderer) MinSize() fyne.Size {
	ts := fyne.MeasureText(r.link.Text, TextBody, StyleBody)
	return fyne.NewSize(ts.Width, ts.Height+3)
}

func (r *linkRenderer) Layout(size fyne.Size) {
	ts := fyne.MeasureText(r.link.Text, TextBody, StyleBody)
	r.txt.Move(fyne.NewPos(0, 0))
	r.txt.Resize(fyne.NewSize(size.Width, ts.Height))
	r.ul.Move(fyne.NewPos(0, ts.Height+1))
	r.ul.Resize(fyne.NewSize(min(ts.Width, size.Width), BorderThin))
}

func (r *linkRenderer) Refresh() {
	r.txt.Text = r.link.Text
	r.txt.Color = ColorBlue
	r.ul.FillColor = ColorBlue
	r.txt.Refresh()
	r.ul.Refresh()
}
