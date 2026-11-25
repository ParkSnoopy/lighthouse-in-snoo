package rawblock

import (
	"fmt"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// AlertSeverity classifies a copyable RawBlock diagnostic modal.
type AlertSeverity int

const (
	AlertWarning AlertSeverity = iota
	AlertError
)

// String returns the uppercase severity label ("WARNING" or "ERROR").
func (s AlertSeverity) String() string {
	if s == AlertError {
		return "ERROR"
	}
	return "WARNING"
}

// AlertModal renders a RawBlock elevated (5px) zero-shadow diagnostic modal for errors
// and warnings with a selectable, read-only Space Mono detail box and a one-click COPY action.
type AlertModal struct {
	widget.BaseWidget

	Severity AlertSeverity
	Title    string
	Detail   string

	CopyBtn  *Button
	CloseBtn *Button
	content  *Card
}

// NewAlertModal constructs a RawBlock error/warning modal with copyable diagnostic detail.
func NewAlertModal(severity AlertSeverity, title, detail string, onCopy func(string), onClose func()) *AlertModal {
	upperTitle := strings.ToUpper(strings.TrimSpace(title))
	if upperTitle == "" {
		upperTitle = severity.String()
	}
	trimmedDetail := strings.TrimSpace(detail)
	if trimmedDetail == "" {
		trimmedDetail = upperTitle
	}

	m := &AlertModal{
		Severity: severity,
		Title:    upperTitle,
		Detail:   trimmedDetail,
	}

	tone := ChipWarning
	if severity == AlertError {
		tone = ChipError
	}

	headerBG := canvas.NewRectangle(ColorBlack)
	headerBG.CornerRadius = RadiusNone
	headerInner := container.NewBorder(
		nil, nil, nil,
		NewStatusChip(severity.String(), tone),
		NewH4(upperTitle, ColorWhite),
	)
	header := container.NewStack(headerBG, InsetBox(Sp2, Sp3, Sp2, Sp3, headerInner))

	// Read-only selectable multi-line borderless Entry inside a single 3px RawBlock frame
	// so users can highlight/copy substrings directly without accidental edits or double boxes.
	detailEntry := &rawEntry{}
	detailEntry.MultiLine = true
	detailEntry.Wrapping = fyne.TextWrapWord
	detailEntry.TextStyle = StyleMono
	detailEntry.Text = trimmedDetail
	detailEntry.ExtendBaseWidget(detailEntry)
	detailEntry.OnChanged = func(s string) {
		if s != trimmedDetail {
			detailEntry.SetText(trimmedDetail)
		}
	}
	detailThemed := container.NewThemeOverride(detailEntry, &inputInnerTheme{})
	detailFrame := newSquareFrame(ColorSurfaceSunken, ColorBlack, BorderThick,
		InsetBox(Sp2, Sp2, Sp2, Sp2, detailThemed))
	detailBox := newMinSizeWrap(fyne.NewSize(520, 140), detailFrame)

	m.CopyBtn = NewButton("COPY", ButtonPrimary, ButtonMedium, func() {
		if onCopy != nil {
			onCopy(m.CopyText())
		}
		m.CopyBtn.SetText("COPIED")
	})
	m.CloseBtn = NewButton("CLOSE", ButtonSecondary, ButtonMedium, func() {
		if onClose != nil {
			onClose()
		}
	})

	body := GapVBox(Sp3,
		header,
		detailBox,
		GapHBox(Sp2, m.CopyBtn, m.CloseBtn),
	)
	m.content = NewCard(body, CardElevated)
	m.ExtendBaseWidget(m)
	return m
}

// CopyText returns the full formatted diagnostic string copied to clipboard.
func (m *AlertModal) CopyText() string {
	return fmt.Sprintf("[%s] %s\n%s", m.Severity.String(), m.Title, m.Detail)
}

func (m *AlertModal) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(m.content)
}

type squareFrame struct {
	widget.BaseWidget
	outer  *canvas.Rectangle
	inner  *canvas.Rectangle
	border float32
	child  fyne.CanvasObject
}

func newSquareFrame(fillColor, borderColor color.Color, borderW float32, child fyne.CanvasObject) *squareFrame {
	outer := canvas.NewRectangle(borderColor)
	outer.CornerRadius = RadiusNone
	inner := canvas.NewRectangle(fillColor)
	inner.CornerRadius = RadiusNone
	sf := &squareFrame{
		outer:  outer,
		inner:  inner,
		border: borderW,
		child:  child,
	}
	sf.ExtendBaseWidget(sf)
	return sf
}

func (f *squareFrame) CreateRenderer() fyne.WidgetRenderer {
	return &squareFrameRenderer{f: f, objs: []fyne.CanvasObject{f.outer, f.inner, f.child}}
}

type squareFrameRenderer struct {
	f    *squareFrame
	objs []fyne.CanvasObject
}

func (r *squareFrameRenderer) Destroy()                     {}
func (r *squareFrameRenderer) Objects() []fyne.CanvasObject { return r.objs }
func (r *squareFrameRenderer) MinSize() fyne.Size {
	ms := r.f.child.MinSize()
	return fyne.NewSize(ms.Width+r.f.border*2, ms.Height+r.f.border*2)
}
func (r *squareFrameRenderer) Layout(size fyne.Size) {
	bw := r.f.border
	r.f.outer.Move(fyne.NewPos(0, 0))
	r.f.outer.Resize(size)
	r.f.inner.Move(fyne.NewPos(bw, bw))
	r.f.inner.Resize(fyne.NewSize(max(size.Width-bw*2, 0), max(size.Height-bw*2, 0)))
	r.f.child.Move(fyne.NewPos(bw, bw))
	r.f.child.Resize(fyne.NewSize(max(size.Width-bw*2, 0), max(size.Height-bw*2, 0)))
}
func (r *squareFrameRenderer) Refresh() {
	r.f.outer.Refresh()
	r.f.inner.Refresh()
	r.f.child.Refresh()
	r.Layout(r.f.Size())
}

type minSizeWrap struct {
	widget.BaseWidget
	min   fyne.Size
	child fyne.CanvasObject
}

func newMinSizeWrap(min fyne.Size, child fyne.CanvasObject) *minSizeWrap {
	w := &minSizeWrap{min: min, child: child}
	w.ExtendBaseWidget(w)
	return w
}

func (w *minSizeWrap) CreateRenderer() fyne.WidgetRenderer {
	return &minSizeWrapRenderer{w: w, objs: []fyne.CanvasObject{w.child}}
}

type minSizeWrapRenderer struct {
	w    *minSizeWrap
	objs []fyne.CanvasObject
}

func (r *minSizeWrapRenderer) Destroy()                     {}
func (r *minSizeWrapRenderer) Objects() []fyne.CanvasObject { return r.objs }
func (r *minSizeWrapRenderer) MinSize() fyne.Size {
	ms := r.w.child.MinSize()
	return fyne.NewSize(max(ms.Width, r.w.min.Width), max(ms.Height, r.w.min.Height))
}
func (r *minSizeWrapRenderer) Layout(size fyne.Size) {
	r.w.child.Move(fyne.NewPos(0, 0))
	r.w.child.Resize(size)
}
func (r *minSizeWrapRenderer) Refresh() {
	r.w.child.Refresh()
	r.Layout(r.w.Size())
}
