package rawblock

import (
	_ "embed"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

//go:embed fonts/ArchivoBlack-Regular.ttf
var fontArchivoBlackData []byte

//go:embed fonts/WorkSans-Regular.ttf
var fontWorkSansRegularData []byte

//go:embed fonts/WorkSans-SemiBold.ttf
var fontWorkSansSemiBoldData []byte

//go:embed fonts/SpaceMono-Regular.ttf
var fontSpaceMonoRegularData []byte

//go:embed fonts/SpaceMono-Bold.ttf
var fontSpaceMonoBoldData []byte

var (
	resArchivoBlack     = fyne.NewStaticResource("ArchivoBlack-Regular.ttf", fontArchivoBlackData)
	resWorkSansRegular  = fyne.NewStaticResource("WorkSans-Regular.ttf", fontWorkSansRegularData)
	resWorkSansSemiBold = fyne.NewStaticResource("WorkSans-SemiBold.ttf", fontWorkSansSemiBoldData)
	resSpaceMonoRegular = fyne.NewStaticResource("SpaceMono-Regular.ttf", fontSpaceMonoRegularData)
	resSpaceMonoBold    = fyne.NewStaticResource("SpaceMono-Bold.ttf", fontSpaceMonoBoldData)
)

// RawBlock design system color tokens.
// Blue (#0000FF) is reserved strictly for hyperlinks and Info semantics.
var (
	ColorBlack            = color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xFF}
	ColorWhite            = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	ColorBlue             = color.NRGBA{R: 0x00, G: 0x00, B: 0xFF, A: 0xFF}
	ColorSurfaceBase      = ColorWhite
	ColorSurfaceInverted  = ColorBlack
	ColorSuccess          = color.NRGBA{R: 0x00, G: 0x80, B: 0x00, A: 0xFF}
	ColorWarning          = color.NRGBA{R: 0xFF, G: 0xA5, B: 0x00, A: 0xFF}
	ColorError            = color.NRGBA{R: 0xFF, G: 0x00, B: 0x00, A: 0xFF}
	ColorInfo             = ColorBlue
	ColorSurfaceSunken    = color.NRGBA{R: 0xF0, G: 0xF0, B: 0xF0, A: 0xFF}
	ColorSurfaceHover     = color.NRGBA{R: 0xE8, G: 0xE8, B: 0xE8, A: 0xFF}
	ColorSurfaceDisabled  = color.NRGBA{R: 0xF5, G: 0xF5, B: 0xF5, A: 0xFF}
	ColorBorderDisabled   = color.NRGBA{R: 0xCC, G: 0xCC, B: 0xCC, A: 0xFF}
	ColorContentPrimary   = ColorBlack
	ColorContentSecondary = color.NRGBA{R: 0x4A, G: 0x4A, B: 0x4A, A: 0xFF}
	ColorContentTertiary  = color.NRGBA{R: 0x76, G: 0x76, B: 0x76, A: 0xFF}
	ColorSelectionBG      = color.NRGBA{R: 0xD0, G: 0xD0, B: 0xD0, A: 0xFF}
)

// RawBlock design system spacing, radius, border weight, and typography scale tokens.
const (
	Sp1 float32 = 4
	Sp2 float32 = 8
	Sp3 float32 = 16
	Sp4 float32 = 24
	Sp5 float32 = 40
	Sp6 float32 = 64
	Sp7 float32 = 80
	Sp8 float32 = 120

	RadiusNone float32 = 0

	BorderThin  float32 = 1
	BorderMid   float32 = 2
	BorderThick float32 = 3
	BorderHeavy float32 = 5

	TextMin        float32 = 14
	TextH1         float32 = 64
	TextH2         float32 = 48
	TextH3         float32 = 32
	TextH4         float32 = 22
	TextBody       float32 = 16
	TextMono       float32 = 15
	TextSmall      float32 = 14
	TextTooltip    float32 = TextMin
	TextTiny       float32 = TextMin
	TextStatusChip float32 = TextMin
	TextFilterChip float32 = TextMin

	LineHeightH1    float32 = 1.0
	LineHeightH2    float32 = 1.05
	LineHeightH3    float32 = 1.1
	LineHeightH4    float32 = 1.2
	LineHeightBody  float32 = 1.6
	LineHeightSmall float32 = 1.5
	LineHeightTiny  float32 = 1.4
	LineHeightMono  float32 = 1.5

	ButtonTracking float32 = 2
	ChipTracking   float32 = 1
)

// RawBlock Fyne TextStyle mappings:
//   - StyleBody     -> Work Sans Regular
//   - StyleHeadline -> Archivo Black Regular
//   - StyleSemiBold -> Work Sans SemiBold
//   - StyleMono     -> Space Mono Regular
//   - StyleMonoBold -> Space Mono Bold
var (
	StyleBody     = fyne.TextStyle{}
	StyleHeadline = fyne.TextStyle{Bold: true}
	StyleSemiBold = fyne.TextStyle{Bold: true, Italic: true}
	StyleMono     = fyne.TextStyle{Monospace: true}
	StyleMonoBold = fyne.TextStyle{Monospace: true, Bold: true}
)

// Theme implements fyne.Theme for the RawBlock brutalist design system:
// zero border radius, zero shadows, strict black-on-white surfaces, thick borders,
// and embedded Archivo Black / Work Sans / Space Mono typography.
type Theme struct{}

var _ fyne.Theme = (*Theme)(nil)

// NewTheme returns the RawBlock brutalist Fyne theme.
func NewTheme() fyne.Theme {
	return &Theme{}
}

// Color resolves RawBlock theme colors regardless of OS light/dark preference.
func (t *Theme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground,
		theme.ColorNameOverlayBackground,
		theme.ColorNameMenuBackground,
		theme.ColorNameHeaderBackground,
		theme.ColorNameButton,
		theme.ColorNameForegroundOnPrimary,
		theme.ColorNameForegroundOnError,
		theme.ColorNameForegroundOnSuccess,
		theme.ColorNameForegroundOnWarning,
		theme.ColorNameScrollBarBackground:
		return ColorWhite

	case theme.ColorNameForeground,
		theme.ColorNamePrimary,
		theme.ColorNameSeparator,
		theme.ColorNameInputBorder,
		theme.ColorNameFocus,
		theme.ColorNameScrollBar,
		theme.ColorNameInnerWindowBorder:
		return ColorBlack

	case theme.ColorNameHyperlink:
		return ColorBlue

	case theme.ColorNameSuccess:
		return ColorSuccess

	case theme.ColorNameWarning:
		return ColorWarning

	case theme.ColorNameError:
		return ColorError

	case theme.ColorNameInputBackground:
		return ColorSurfaceSunken

	case theme.ColorNameHover:
		return ColorSurfaceHover

	case theme.ColorNamePressed:
		return ColorBlack

	case theme.ColorNameSelection:
		return ColorSelectionBG

	case theme.ColorNamePlaceHolder, theme.ColorNameDisabled:
		return ColorContentTertiary

	case theme.ColorNameDisabledButton:
		return ColorSurfaceSunken

	case theme.ColorNameInnerWindowBorderInactive:
		return ColorBorderDisabled

	case theme.ColorNameShadow:
		return color.Transparent

	default:
		return ColorBlack
	}
}

// Font returns embedded Archivo Black, Work Sans, or Space Mono resources.
func (t *Theme) Font(style fyne.TextStyle) fyne.Resource {
	if style.Monospace {
		if style.Bold {
			return resSpaceMonoBold
		}
		return resSpaceMonoRegular
	}
	if style.Bold && style.Italic {
		return resWorkSansSemiBold
	}
	if style.Bold {
		return resArchivoBlack
	}
	return resWorkSansRegular
}

// Icon delegates to Fyne's default icon set; RawBlock components avoid decorative icons.
func (t *Theme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

// Size enforces 0px radii everywhere, zero modal blur, and RawBlock border/type metrics.
func (t *Theme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameButtonRadius,
		theme.SizeNameCardRadius,
		theme.SizeNameDialogRadius,
		theme.SizeNamePopupRadius,
		theme.SizeNameMenuRadius,
		theme.SizeNameInputRadius,
		theme.SizeNameSelectionRadius,
		theme.SizeNameScrollBarRadius,
		theme.SizeNameInnerWindowRadius,
		theme.SizeNameWindowButtonRadius,
		theme.SizeNameModalBlurRadius:
		return RadiusNone

	case theme.SizeNameSeparatorThickness, theme.SizeNameSplitThickness, theme.SizeNameInputBorder:
		return BorderThick

	case theme.SizeNameText:
		return TextBody

	case theme.SizeNameCaptionText:
		return TextTiny

	case theme.SizeNameHeadingText:
		return TextH3

	case theme.SizeNameSubHeadingText:
		return TextH4

	case theme.SizeNamePadding:
		return Sp2

	case theme.SizeNameInnerPadding:
		return 10

	case theme.SizeNameLineSpacing:
		return Sp1

	case theme.SizeNameScrollBar:
		return 10

	case theme.SizeNameScrollBarSmall:
		return 6

	default:
		return theme.DefaultTheme().Size(name)
	}
}

// inputInnerTheme removes Fyne's stock Entry border/fill so Input draws exact 3px/5px frames.
type inputInnerTheme struct {
	Theme
}

func (t *inputInnerTheme) Color(name fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameInputBackground,
		theme.ColorNameInputBorder,
		theme.ColorNameFocus,
		theme.ColorNameScrollBar,
		theme.ColorNameScrollBarBackground:
		return color.Transparent
	default:
		return t.Theme.Color(name, v)
	}
}

func (t *inputInnerTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameInputBorder:
		return 2 // Crisp 2px black caret width
	case theme.SizeNameText:
		return TextMono
	case theme.SizeNameInnerPadding:
		return 4
	case theme.SizeNameScrollBar, theme.SizeNameScrollBarSmall:
		return 0
	default:
		return t.Theme.Size(name)
	}
}

// --- Typography Scale Constructors ---

// NewH1 creates an Archivo Black 64px heading.
func NewH1(text string, c color.Color) *canvas.Text {
	return newStyledText(strings.ToUpper(text), TextH1, StyleHeadline, c)
}

// NewH2 creates an Archivo Black 48px heading.
func NewH2(text string, c color.Color) *canvas.Text {
	return newStyledText(strings.ToUpper(text), TextH2, StyleHeadline, c)
}

// NewH3 creates an Archivo Black 32px heading.
func NewH3(text string, c color.Color) *canvas.Text {
	return newStyledText(strings.ToUpper(text), TextH3, StyleHeadline, c)
}

// NewH4 creates a Work Sans 22px semibold heading.
func NewH4(text string, c color.Color) *canvas.Text {
	return newStyledText(text, TextH4, StyleSemiBold, c)
}

// NewBody creates a Work Sans 16px regular body text object.
func NewBody(text string, c color.Color) *canvas.Text {
	return newStyledText(text, TextBody, StyleBody, c)
}

// NewSmall creates a Work Sans 14px regular text object.
func NewSmall(text string, c color.Color) *canvas.Text {
	return newStyledText(text, TextSmall, StyleBody, c)
}

// NewTiny creates a Work Sans caption/helper text object (clamped to TextMin = 14px).
func NewTiny(text string, c color.Color) *canvas.Text {
	return newStyledText(text, TextTiny, StyleBody, c)
}

// NewMono creates a Space Mono 15px regular text object.
func NewMono(text string, c color.Color) *canvas.Text {
	return newStyledText(text, TextMono, StyleMono, c)
}

// NewLabel creates an Archivo Black 14px regular uppercase form/section label.
func NewLabel(text string, c color.Color) *canvas.Text {
	return newStyledText(strings.ToUpper(text), TextSmall, StyleHeadline, c)
}

func newStyledText(text string, size float32, style fyne.TextStyle, c color.Color) *canvas.Text {
	if c == nil {
		c = ColorBlack
	}
	t := canvas.NewText(text, c)
	t.TextSize = max(size, TextMin)
	t.TextStyle = style
	return t
}

// NewDivider creates a solid black horizontal rule of thickness (default BorderThick = 3px).
func NewDivider(thickness float32) *canvas.Rectangle {
	if thickness <= 0 {
		thickness = BorderThick
	}
	r := canvas.NewRectangle(ColorBlack)
	r.CornerRadius = RadiusNone
	r.SetMinSize(fyne.NewSize(1, thickness))
	return r
}

// TrackedText renders a single-line string with exact pixel letter tracking (e.g. 2px buttons, 1px chips).
type TrackedText struct {
	widget.BaseWidget

	Text      string
	TextSize  float32
	TextStyle fyne.TextStyle
	Color     color.Color
	Tracking  float32
	Alignment fyne.TextAlign
}

// NewTrackedText constructs a pixel-tracked text primitive (clamped to TextMin = 14px).
func NewTrackedText(text string, size float32, style fyne.TextStyle, c color.Color, tracking float32) *TrackedText {
	if c == nil {
		c = ColorBlack
	}
	tt := &TrackedText{
		Text:      text,
		TextSize:  max(size, TextMin),
		TextStyle: style,
		Color:     c,
		Tracking:  tracking,
		Alignment: fyne.TextAlignCenter,
	}
	tt.ExtendBaseWidget(tt)
	return tt
}

func (t *TrackedText) CreateRenderer() fyne.WidgetRenderer {
	r := &trackedTextRenderer{tt: t}
	r.rebuild()
	return r
}

type trackedTextRenderer struct {
	tt      *TrackedText
	runes   []*canvas.Text
	objects []fyne.CanvasObject
	lastTxt string
}

func (r *trackedTextRenderer) Destroy() {}

func (r *trackedTextRenderer) rebuild() {
	rs := []rune(r.tt.Text)
	r.runes = make([]*canvas.Text, len(rs))
	r.objects = make([]fyne.CanvasObject, len(rs))
	for i, ch := range rs {
		gt := canvas.NewText(string(ch), r.tt.Color)
		gt.TextSize = r.tt.TextSize
		gt.TextStyle = r.tt.TextStyle
		r.runes[i] = gt
		r.objects[i] = gt
	}
	r.lastTxt = r.tt.Text
}

func (r *trackedTextRenderer) measureTracked() (totalW, maxH float32, widths []float32) {
	if r.tt.Text != r.lastTxt {
		r.rebuild()
	}
	widths = make([]float32, len(r.runes))
	for i, gt := range r.runes {
		ms := fyne.MeasureText(gt.Text, r.tt.TextSize, r.tt.TextStyle)
		widths[i] = ms.Width
		totalW += ms.Width
		if ms.Height > maxH {
			maxH = ms.Height
		}
	}
	if len(r.runes) > 1 {
		totalW += r.tt.Tracking * float32(len(r.runes)-1)
	}
	if maxH == 0 {
		maxH = fyne.MeasureText("M", r.tt.TextSize, r.tt.TextStyle).Height
	}
	return totalW, maxH, widths
}

func (r *trackedTextRenderer) MinSize() fyne.Size {
	w, h, _ := r.measureTracked()
	return fyne.NewSize(w, h)
}

func (r *trackedTextRenderer) Layout(size fyne.Size) {
	totalW, maxH, widths := r.measureTracked()
	var x float32
	switch r.tt.Alignment {
	case fyne.TextAlignTrailing:
		x = max(size.Width-totalW, 0)
	case fyne.TextAlignCenter:
		x = max((size.Width-totalW)/2, 0)
	default:
		x = 0
	}
	y := (size.Height - maxH) / 2
	for i, gt := range r.runes {
		gt.Move(fyne.NewPos(x, y))
		gt.Resize(fyne.NewSize(widths[i], maxH))
		x += widths[i] + r.tt.Tracking
	}
}

func (r *trackedTextRenderer) Refresh() {
	if r.tt.Text != r.lastTxt {
		r.rebuild()
	}
	for _, gt := range r.runes {
		gt.TextSize = r.tt.TextSize
		gt.TextStyle = r.tt.TextStyle
		gt.Color = r.tt.Color
		gt.Refresh()
	}
	r.Layout(r.tt.Size())
}

func (r *trackedTextRenderer) Objects() []fyne.CanvasObject {
	if r.tt.Text != r.lastTxt {
		r.rebuild()
	}
	return r.objects
}
