package rawblock

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
)

type insetLayout struct {
	top, right, bottom, left float32
}

// InsetBox pads a single child with exact RawBlock pixel insets.
func InsetBox(top, right, bottom, left float32, obj fyne.CanvasObject) *fyne.Container {
	return container.New(&insetLayout{top: top, right: right, bottom: bottom, left: left}, obj)
}

func (l *insetLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var w, h float32
	for _, o := range objects {
		if !o.Visible() {
			continue
		}
		ms := o.MinSize()
		w = max(w, ms.Width)
		h = max(h, ms.Height)
	}
	return fyne.NewSize(w+l.left+l.right, h+l.top+l.bottom)
}

func (l *insetLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	innerW := max(size.Width-l.left-l.right, 0)
	innerH := max(size.Height-l.top-l.bottom, 0)
	pos := fyne.NewPos(l.left, l.top)
	inner := fyne.NewSize(innerW, innerH)
	for _, o := range objects {
		o.Move(pos)
		o.Resize(inner)
	}
}

type gapVBoxLayout struct {
	gap float32
}

// GapVBox stacks children vertically with exact pixel gap spacing.
func GapVBox(gap float32, objs ...fyne.CanvasObject) *fyne.Container {
	return container.New(&gapVBoxLayout{gap: gap}, objs...)
}

func (l *gapVBoxLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var w, h float32
	visible := 0
	for _, o := range objects {
		if !o.Visible() {
			continue
		}
		ms := o.MinSize()
		w = max(w, ms.Width)
		h += ms.Height
		visible++
	}
	if visible > 1 {
		h += l.gap * float32(visible-1)
	}
	return fyne.NewSize(w, h)
}

func (l *gapVBoxLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	y := float32(0)
	for _, o := range objects {
		if !o.Visible() {
			continue
		}
		h := o.MinSize().Height
		o.Move(fyne.NewPos(0, y))
		o.Resize(fyne.NewSize(size.Width, h))
		y += h + l.gap
	}
}

type gapHBoxLayout struct {
	gap float32
}

// GapHBox places children horizontally centered vertically with exact pixel gap spacing.
func GapHBox(gap float32, objs ...fyne.CanvasObject) *fyne.Container {
	return container.New(&gapHBoxLayout{gap: gap}, objs...)
}

func (l *gapHBoxLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var w, h float32
	visible := 0
	for _, o := range objects {
		if !o.Visible() {
			continue
		}
		ms := o.MinSize()
		w += ms.Width
		h = max(h, ms.Height)
		visible++
	}
	if visible > 1 {
		w += l.gap * float32(visible-1)
	}
	return fyne.NewSize(w, h)
}

func (l *gapHBoxLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	x := float32(0)
	for _, o := range objects {
		if !o.Visible() {
			continue
		}
		ms := o.MinSize()
		o.Move(fyne.NewPos(x, (size.Height-ms.Height)/2))
		o.Resize(fyne.NewSize(ms.Width, ms.Height))
		x += ms.Width + l.gap
	}
}

type asymmetricSplitLayout struct {
	leftRatio float32
	gap       float32
}

// AsymmetricSplit arranges two panels side-by-side with intentional brutalist ratio and gap.
func AsymmetricSplit(leftRatio, gap float32, left, right fyne.CanvasObject) *fyne.Container {
	return container.New(&asymmetricSplitLayout{leftRatio: leftRatio, gap: gap}, left, right)
}

func (l *asymmetricSplitLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	if len(objects) < 2 {
		return fyne.NewSize(0, 0)
	}
	m0 := objects[0].MinSize()
	m1 := objects[1].MinSize()
	return fyne.NewSize(m0.Width+m1.Width+l.gap, max(m0.Height, m1.Height))
}

func (l *asymmetricSplitLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	if len(objects) < 2 {
		return
	}
	avail := max(size.Width-l.gap, 0)
	lw := max(avail*l.leftRatio, objects[0].MinSize().Width)
	if lw > avail-objects[1].MinSize().Width {
		lw = avail * l.leftRatio
	}
	rw := max(avail-lw, 0)
	objects[0].Move(fyne.NewPos(0, 0))
	objects[0].Resize(fyne.NewSize(lw, size.Height))
	objects[1].Move(fyne.NewPos(lw+l.gap, 0))
	objects[1].Resize(fyne.NewSize(rw, size.Height))
}
