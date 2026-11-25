package ui

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"lighthouse-in-snoo/internal/ui/rawblock"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/peer"
	"lighthouse-in-snoo/pkg/tun"
)

// Options configures the Fyne TUN interface controller.
type Options struct {
	KeyPair          *identity.KeyPair
	BlacklistPath    string
	HubURL           string
	HubPassphrase    string
	STUNServerURI    string
	TLSConfig        *tls.Config
	TCPOnly          bool
	AllowInsecureICE bool
	IncludeLoopback  bool
	InterfaceName    string
	OpenDevice       func(localIP netip.Addr) (tun.Device, error)
	Logger           *slog.Logger
}

type pendingConsent struct {
	req    peer.IncomingRequest
	respCh chan peer.ConsentDecision
	popup  *widget.PopUp
}

// Controller binds a RawBlock-styled Fyne desktop UI to a Lighthouse peer Client
// and OS TUN Router. All incoming connections require explicit Allow / Deny / Blacklist action.
type Controller struct {
	app    fyne.App
	window fyne.Window
	opts   Options
	vip    netip.Addr

	mu               sync.Mutex
	uiMu             sync.Mutex
	client           *peer.Client
	router           *tun.Router
	connected        bool
	joinedPass       string
	joinedChanID     string
	broadcasting     bool
	activeTab        int
	peers            []peer.DiscoveredPeer
	routes           []tun.RouteInfo
	blacklisted      []string
	consentPrompting bool
	activeConsent    *pendingConsent

	// Exposed RawBlock components for user interaction and deterministic Fyne headless tests.
	StatusChip      *rawblock.Chip
	StatusText      *canvas.Text
	PeerIDText      *canvas.Text
	VirtualIPText   *canvas.Text
	InterfaceText   *canvas.Text
	HubURLInput     *rawblock.Input
	HubPassInput    *rawblock.Input
	IfNameInput     *rawblock.Input
	HubURLEntry     *widget.Entry
	HubPassEntry    *widget.Entry
	IfNameEntry     *widget.Entry
	TCPOnlyCheck    *rawblock.Check
	ConnectHubBtn   *rawblock.Button
	PassphraseInput *rawblock.Input
	DisplayInput    *rawblock.Input
	PassphraseEntry *widget.Entry
	DisplayEntry    *widget.Entry
	JoinBtn         *rawblock.Button
	BroadcastCheck  *rawblock.Check
	DirectPeerInput *rawblock.Input
	DirectPeerEntry *widget.Entry
	DirectConnBtn   *rawblock.Button
	TabPeersChip    *rawblock.Chip
	TabTunnelsChip  *rawblock.Chip
	TabBlockChip    *rawblock.Chip
	tabContent      *fyne.Container
	peersPanel      fyne.CanvasObject
	tunnelsPanel    fyne.CanvasObject
	blacklistPanel  fyne.CanvasObject
	PeersBox        *fyne.Container
	TunnelsBox      *fyne.Container
	BlacklistBox    *fyne.Container
}

// NewController applies the RawBlock theme, constructs the brutalist Fyne window, and wires
// controls for TUN binding, passphrase-scoped broadcasting, peer connection, consent, and blacklisting.
func NewController(a fyne.App, opts Options) (*Controller, error) {
	if opts.KeyPair == nil {
		kp, err := identity.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		opts.KeyPair = kp
	}
	if opts.InterfaceName == "" {
		opts.InterfaceName = "lh0"
	}
	if opts.HubURL == "" {
		opts.HubURL = "wss://localhost:8443/v1/signal"
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	vip, err := identity.VirtualIPv4FromPeerID(opts.KeyPair.PeerID)
	if err != nil {
		return nil, err
	}

	a.Settings().SetTheme(rawblock.NewTheme())

	w := a.NewWindow("LIGHTHOUSE")
	w.Resize(fyne.NewSize(1120, 820))

	c := &Controller{
		app:    a,
		window: w,
		opts:   opts,
		vip:    vip,
	}
	c.buildUI()
	return c, nil
}

// Window returns the primary Fyne window.
func (c *Controller) Window() fyne.Window {
	return c.window
}

// Client returns the active peer Client, or nil when disconnected.
func (c *Controller) Client() *peer.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.client
}

// Router returns the bound TUN Router, or nil when unbound.
func (c *Controller) Router() *tun.Router {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.router
}

// PendingRequest returns the currently prompted incoming connection request, if any.
func (c *Controller) PendingRequest() (peer.IncomingRequest, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeConsent == nil {
		return peer.IncomingRequest{}, false
	}
	return c.activeConsent.req, true
}

func (c *Controller) doUI(fn func()) {
	fyne.Do(func() {
		c.uiMu.Lock()
		defer c.uiMu.Unlock()
		fn()
	})
}

func (c *Controller) doUIWait(fn func()) {
	fyne.DoAndWait(func() {
		c.uiMu.Lock()
		defer c.uiMu.Unlock()
		fn()
	})
}

// RespondIncoming delivers an explicit Allow, Deny, or Blacklist decision to the active prompt.
func (c *Controller) RespondIncoming(decision peer.ConsentDecision) bool {
	c.mu.Lock()
	pc := c.activeConsent
	c.activeConsent = nil
	c.consentPrompting = false
	c.mu.Unlock()
	if pc == nil {
		return false
	}
	if pc.popup != nil {
		c.doUI(func() {
			pc.popup.Hide()
		})
	}
	select {
	case pc.respCh <- decision:
		return true
	default:
		return false
	}
}

func (c *Controller) buildUI() {
	// --- Inverted Black Masthead (Archivo Black 48px + Status Chip) ---
	title := rawblock.NewH2("LIGHTHOUSE", rawblock.ColorWhite)
	c.StatusChip = rawblock.NewStatusChip("DISCONNECTED", rawblock.ChipDefault)
	c.StatusText = rawblock.NewMono("UNBOUND", rawblock.ColorWhite)
	c.StatusText.Alignment = fyne.TextAlignTrailing
	mastheadRight := rawblock.GapVBox(rawblock.Sp2,
		container.NewBorder(nil, nil, nil, c.StatusChip),
		c.StatusText,
	)
	mastheadInner := container.NewBorder(nil, nil, nil, mastheadRight, title)
	mastheadBG := canvas.NewRectangle(rawblock.ColorBlack)
	mastheadBG.CornerRadius = rawblock.RadiusNone
	masthead := container.NewBorder(
		nil,
		rawblock.NewDivider(rawblock.BorderHeavy),
		nil,
		nil,
		container.NewStack(mastheadBG, rawblock.InsetBox(rawblock.Sp3, rawblock.Sp4, rawblock.Sp3, rawblock.Sp4, mastheadInner)),
	)

	// --- Left Rail: Elevated (5px border) Node & Hub Binding Card ---
	c.PeerIDText = rawblock.NewMono(shortID(c.opts.KeyPair.PeerID), rawblock.ColorBlack)
	c.VirtualIPText = rawblock.NewMono(c.vip.String(), rawblock.ColorBlack)
	c.InterfaceText = rawblock.NewMono("UNBOUND", rawblock.ColorBlack)

	copyIDBtn := rawblock.NewButton("COPY ID", rawblock.ButtonSecondary, rawblock.ButtonSmall, func() {
		c.app.Clipboard().SetContent(c.opts.KeyPair.PeerID)
		c.setStatus("COPIED", rawblock.ChipDefault)
	})

	nodeMeta := rawblock.GapVBox(rawblock.Sp2,
		rawblock.NewH3("NODE", rawblock.ColorBlack),
		rawblock.NewDivider(rawblock.BorderThick),
		kvRow("PEER ID", container.NewBorder(nil, nil, nil, copyIDBtn,
			rawblock.WithTooltip(c.PeerIDText, c.opts.KeyPair.PeerID))),
		rawblock.AsymmetricSplit(0.52, rawblock.Sp3,
			kvRow("VIRTUAL IP", c.VirtualIPText),
			kvRow("INTERFACE", c.InterfaceText),
		),
	)

	c.HubURLInput = rawblock.NewInput("HUB", "wss://hub.example.com/v1/signal", "", false)
	c.HubURLEntry = c.HubURLInput.Entry
	c.HubURLEntry.SetText(c.opts.HubURL)

	c.HubPassInput = rawblock.NewInput("HUB PASSPHRASE", "OPTIONAL", "", true)
	c.HubPassEntry = c.HubPassInput.Entry
	c.HubPassEntry.SetText(c.opts.HubPassphrase)

	c.IfNameInput = rawblock.NewInput("TUN NAME", "lh0", "", false)
	c.IfNameEntry = c.IfNameInput.Entry
	c.IfNameEntry.SetText(c.opts.InterfaceName)

	c.TCPOnlyCheck = rawblock.NewCheck("TCP ONLY", nil)
	c.TCPOnlyCheck.SetCheckedSilent(c.opts.TCPOnly)

	c.ConnectHubBtn = rawblock.NewButton("BIND & CONNECT", rawblock.ButtonPrimary, rawblock.ButtonMedium, func() {
		go c.toggleConnection()
	})

	leftContent := rawblock.GapVBox(rawblock.Sp3,
		nodeMeta,
		rawblock.NewDivider(rawblock.BorderThick),
		c.HubURLInput,
		c.HubPassInput,
		c.IfNameInput,
		c.TCPOnlyCheck,
		c.ConnectHubBtn,
	)
	leftCard := rawblock.NewCard(leftContent, rawblock.CardElevated)

	// --- Right Column: Default (3px border) Panel with Brutalist Filter Chip Tabs ---
	c.PassphraseInput = rawblock.NewInput("PASSPHRASE", "SHARED PASSPHRASE", "", true)
	c.PassphraseEntry = c.PassphraseInput.Entry

	c.DisplayInput = rawblock.NewInput("LABEL", "PEER LABEL", "", false)
	c.DisplayEntry = c.DisplayInput.Entry

	c.JoinBtn = rawblock.NewButton("JOIN", rawblock.ButtonPrimary, rawblock.ButtonSmall, func() {
		go c.joinChannelAction()
	})

	c.BroadcastCheck = rawblock.NewCheck("BROADCAST", func(enabled bool) {
		go c.broadcastToggleAction(enabled)
	})

	c.DirectPeerInput = rawblock.NewInput("DIRECT PEER ID", "PEER ID", "", false)
	c.DirectPeerEntry = c.DirectPeerInput.Entry
	c.DirectConnBtn = rawblock.NewButton("CONNECT", rawblock.ButtonSecondary, rawblock.ButtonMedium, func() {
		var target string
		c.doUIWait(func() {
			target = strings.TrimSpace(c.DirectPeerEntry.Text)
		})
		if target != "" {
			go c.connectPeerAction(target)
		}
	})

	c.PeersBox = rawblock.GapVBox(0, emptyListRow("NO PEERS"))
	c.TunnelsBox = rawblock.GapVBox(0, emptyListRow("NO ACTIVE TUNNELS"))
	c.BlacklistBox = rawblock.GapVBox(0, emptyListRow("EMPTY"))

	channelRow := rawblock.AsymmetricSplit(0.58, rawblock.Sp3, c.PassphraseInput, c.DisplayInput)
	channelActions := rawblock.GapHBox(rawblock.Sp3, c.JoinBtn, c.BroadcastCheck)
	directRow := container.NewBorder(nil, nil, nil,
		rawblock.InsetBox(0, 0, 0, rawblock.Sp2, container.NewBorder(nil, c.DirectConnBtn, nil, nil)),
		c.DirectPeerInput)

	peersTop := rawblock.GapVBox(rawblock.Sp3,
		channelRow,
		channelActions,
		rawblock.NewDivider(rawblock.BorderThick),
		directRow,
		rawblock.NewDivider(rawblock.BorderThick),
	)
	c.peersPanel = container.NewBorder(peersTop, nil, nil, nil, container.NewVScroll(c.PeersBox))
	c.tunnelsPanel = container.NewVScroll(c.TunnelsBox)
	c.blacklistPanel = container.NewVScroll(c.BlacklistBox)

	c.TabPeersChip = rawblock.NewFilterChip("PEERS", true, func() { c.selectTab(0) })
	c.TabTunnelsChip = rawblock.NewFilterChip("TUNNELS", false, func() { c.selectTab(1) })
	c.TabBlockChip = rawblock.NewFilterChip("BLACKLIST", false, func() { c.selectTab(2) })

	tabBar := rawblock.GapVBox(rawblock.Sp2,
		rawblock.GapHBox(rawblock.Sp2, c.TabPeersChip, c.TabTunnelsChip, c.TabBlockChip),
		rawblock.NewDivider(rawblock.BorderThick),
	)
	c.tabContent = container.NewStack(c.peersPanel)
	rightBody := container.NewBorder(tabBar, nil, nil, nil,
		rawblock.InsetBox(rawblock.Sp3, 0, 0, 0, c.tabContent))
	rightCard := rawblock.NewCard(rightBody, rawblock.CardDefault)

	// --- Asymmetric Root Layout (40% / 60%, Sp4 gutters, white surface base) ---
	mainArea := rawblock.InsetBox(rawblock.Sp4, rawblock.Sp4, rawblock.Sp4, rawblock.Sp4,
		rawblock.AsymmetricSplit(0.40, rawblock.Sp4, leftCard, rightCard))
	rootBG := canvas.NewRectangle(rawblock.ColorSurfaceBase)
	rootBG.CornerRadius = rawblock.RadiusNone
	root := container.NewStack(rootBG, container.NewBorder(masthead, nil, nil, nil, mainArea))
	c.window.SetContent(root)
}

func (c *Controller) selectTab(idx int) {
	c.mu.Lock()
	c.activeTab = idx
	c.mu.Unlock()

	c.doUI(func() {
		c.TabPeersChip.SetActive(idx == 0)
		c.TabTunnelsChip.SetActive(idx == 1)
		c.TabBlockChip.SetActive(idx == 2)
		switch idx {
		case 1:
			c.tabContent.Objects = []fyne.CanvasObject{c.tunnelsPanel}
		case 2:
			c.tabContent.Objects = []fyne.CanvasObject{c.blacklistPanel}
		default:
			c.tabContent.Objects = []fyne.CanvasObject{c.peersPanel}
		}
		c.tabContent.Refresh()
	})
}

func kvRow(label string, val fyne.CanvasObject) fyne.CanvasObject {
	return rawblock.GapVBox(rawblock.Sp1, rawblock.NewLabel(label, rawblock.ColorContentSecondary), val)
}

func emptyListRow(text string) fyne.CanvasObject {
	return rawblock.InsetBox(12, 0, 12, 0, rawblock.NewBody(text, rawblock.ColorContentSecondary))
}

func (c *Controller) setStatus(msg string, tone rawblock.ChipTone) {
	c.doUI(func() {
		c.StatusChip.SetStatus(msg, tone)
	})
}

func (c *Controller) toggleConnection() {
	c.mu.Lock()
	alreadyConnected := c.connected
	c.mu.Unlock()
	if alreadyConnected {
		c.Disconnect()
		return
	}
	if err := c.ConnectAndBind(context.Background()); err != nil {
		c.setStatus("ERROR", rawblock.ChipError)
		c.doUI(func() {
			c.HubURLInput.SetError(err.Error())
		})
	}
}

// ConnectAndBind binds the OS TUN interface and registers with the Lighthouse hub.
func (c *Controller) ConnectAndBind(ctx context.Context) error {
	var (
		hubURL  string
		hubPass string
		ifName  string
		tcpOnly bool
	)
	c.doUIWait(func() {
		c.HubURLInput.SetError("")
		hubURL = strings.TrimSpace(c.HubURLEntry.Text)
		hubPass = c.HubPassEntry.Text
		ifName = strings.TrimSpace(c.IfNameEntry.Text)
		tcpOnly = c.TCPOnlyCheck.Checked
	})
	if ifName == "" {
		ifName = "lh0"
	}

	openFn := c.opts.OpenDevice
	if openFn == nil {
		openFn = func(localIP netip.Addr) (tun.Device, error) {
			return tun.OpenLinux(tun.LinuxConfig{
				Name:        ifName,
				LocalCIDR:   netip.PrefixFrom(localIP, tun.DefaultSubnetPrefixBits),
				MTU:         tun.DefaultMTU,
				ConfigureOS: true,
			})
		}
	}

	dev, err := openFn(c.vip)
	if err != nil {
		return fmt.Errorf("bind interface: %w", err)
	}
	router, err := tun.NewRouter(dev, c.vip)
	if err != nil {
		_ = dev.Close()
		return err
	}

	client, err := peer.NewClient(&peer.Config{
		KeyPair:             c.opts.KeyPair,
		SignalingURL:        hubURL,
		HubPassphrase:       hubPass,
		TLSConfig:           c.opts.TLSConfig,
		STUNServerURI:       c.opts.STUNServerURI,
		TCPOnly:             tcpOnly,
		AllowInsecureICE:    c.opts.AllowInsecureICE,
		IncludeLoopback:     c.opts.IncludeLoopback,
		EnablePacketChannel: true,
		BlacklistPath:       c.opts.BlacklistPath,
		Consent:             c,
		Logger:              c.opts.Logger,
		OnSession: func(s *peer.Session) {
			_, _ = router.AttachSession(s)
			c.refreshLists()
		},
		OnSessionClosed: func(remotePeerID, _ string) {
			router.DetachPeer(remotePeerID)
			c.refreshLists()
		},
		OnPeersChanged: func(_ string, peers []peer.DiscoveredPeer) {
			c.mu.Lock()
			c.peers = peers
			c.mu.Unlock()
			c.refreshLists()
		},
	})
	if err != nil {
		_ = router.Close()
		return err
	}

	regCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err = client.Register(regCtx)
	cancel()
	if err != nil {
		_ = client.Close()
		_ = router.Close()
		return err
	}

	c.mu.Lock()
	c.client = client
	c.router = router
	c.connected = true
	c.blacklisted = client.BlacklistedPeers()
	c.mu.Unlock()

	ifInfo := fmt.Sprintf("%s %s/%d", dev.Name(), c.vip.String(), tun.DefaultSubnetPrefixBits)
	c.doUI(func() {
		c.InterfaceText.Text = ifInfo
		c.InterfaceText.Refresh()
		c.StatusText.Text = ifInfo
		c.StatusText.Refresh()
		c.StatusChip.SetStatus("CONNECTED", rawblock.ChipActive)
		c.ConnectHubBtn.SetText("DISCONNECT")
		c.ConnectHubBtn.SetVariant(rawblock.ButtonSecondary)
	})
	c.refreshLists()
	return nil
}

// Disconnect closes all peer tunnels, hub WSS, and the bound TUN interface.
func (c *Controller) Disconnect() {
	c.mu.Lock()
	client := c.client
	router := c.router
	c.client = nil
	c.router = nil
	c.connected = false
	c.broadcasting = false
	c.joinedChanID = ""
	c.joinedPass = ""
	c.peers = nil
	c.routes = nil
	c.mu.Unlock()

	if client != nil {
		_ = client.Close()
	}
	if router != nil {
		_ = router.Close()
	}

	c.doUI(func() {
		c.BroadcastCheck.SetCheckedSilent(false)
		c.InterfaceText.Text = "UNBOUND"
		c.InterfaceText.Refresh()
		c.StatusText.Text = "UNBOUND"
		c.StatusText.Refresh()
		c.StatusChip.SetStatus("DISCONNECTED", rawblock.ChipDefault)
		c.ConnectHubBtn.SetText("BIND & CONNECT")
		c.ConnectHubBtn.SetVariant(rawblock.ButtonPrimary)
	})
	c.refreshLists()
}

func (c *Controller) joinChannelAction() {
	var pass string
	c.doUIWait(func() {
		c.PassphraseInput.SetError("")
		pass = c.PassphraseEntry.Text
	})
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil {
		c.setStatus("OFFLINE", rawblock.ChipWarning)
		return
	}
	chID, err := client.JoinChannel(context.Background(), pass)
	if err != nil {
		c.setStatus("JOIN ERROR", rawblock.ChipError)
		c.doUI(func() { c.PassphraseInput.SetError(err.Error()) })
		return
	}
	c.mu.Lock()
	c.joinedPass = pass
	c.joinedChanID = chID
	c.mu.Unlock()
	c.setStatus("LISTENING", rawblock.ChipActive)
}

func (c *Controller) broadcastToggleAction(enabled bool) {
	var pass, label string
	c.doUIWait(func() {
		c.PassphraseInput.SetError("")
		pass = c.PassphraseEntry.Text
		label = strings.TrimSpace(c.DisplayEntry.Text)
	})
	c.mu.Lock()
	client := c.client
	if pass == "" {
		pass = c.joinedPass
	}
	c.mu.Unlock()
	if client == nil {
		if enabled {
			c.doUI(func() { c.BroadcastCheck.SetCheckedSilent(false) })
			c.setStatus("OFFLINE", rawblock.ChipWarning)
		}
		return
	}
	if _, err := client.SetBroadcast(context.Background(), enabled, pass, label); err != nil {
		c.doUI(func() {
			c.BroadcastCheck.SetCheckedSilent(!enabled)
			c.PassphraseInput.SetError(err.Error())
		})
		c.setStatus("BROADCAST ERR", rawblock.ChipError)
		return
	}
	c.mu.Lock()
	c.broadcasting = enabled
	c.mu.Unlock()
	if enabled {
		c.setStatus("BROADCASTING", rawblock.ChipWarning)
	} else {
		c.setStatus("CONNECTED", rawblock.ChipActive)
	}
}

func (c *Controller) connectPeerAction(targetPeerID string) {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil {
		c.setStatus("OFFLINE", rawblock.ChipWarning)
		return
	}
	c.setStatus("CONNECTING", rawblock.ChipWarning)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.Connect(ctx, targetPeerID); err != nil {
		c.setStatus("CONNECT ERR", rawblock.ChipError)
		return
	}
	c.setStatus("CONNECTED", rawblock.ChipActive)
	c.refreshLists()
}

func (c *Controller) blacklistPeerAction(peerID string) {
	c.mu.Lock()
	client := c.client
	router := c.router
	c.mu.Unlock()
	if client == nil {
		return
	}
	if err := client.Blacklist(peerID); err != nil {
		c.setStatus("BLOCK ERR", rawblock.ChipError)
		return
	}
	if router != nil {
		router.DetachPeer(peerID)
	}
	c.setStatus("BLACKLISTED", rawblock.ChipError)
	c.refreshLists()
}

func (c *Controller) unblacklistPeerAction(peerID string) {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil {
		return
	}
	_ = client.Unblacklist(peerID)
	c.setStatus("CONNECTED", rawblock.ChipActive)
	c.refreshLists()
}

// AuthorizeIncoming implements peer.ConsentHandler with an elevated 5px-bordered RawBlock modal.
func (c *Controller) AuthorizeIncoming(ctx context.Context, req *peer.IncomingRequest) peer.ConsentDecision {
	if req == nil {
		return peer.ConsentDeny
	}
	pc := &pendingConsent{
		req:    *req,
		respCh: make(chan peer.ConsentDecision, 1),
	}

	c.mu.Lock()
	if c.consentPrompting || c.activeConsent != nil {
		c.mu.Unlock()
		return peer.ConsentDeny
	}
	c.consentPrompting = true
	c.mu.Unlock()

	fpShort := ""
	if len(req.DTLSFingerprints) > 0 {
		fpShort = req.DTLSFingerprints[0]
		if len(fpShort) > 29 {
			fpShort = fpShort[:29] + "..."
		}
	}
	nameText := req.DisplayName
	if nameText == "" {
		nameText = "(UNLABELED)"
	}

	c.doUIWait(func() {
		headerBG := canvas.NewRectangle(rawblock.ColorBlack)
		headerBG.CornerRadius = rawblock.RadiusNone
		header := container.NewStack(headerBG, rawblock.InsetBox(rawblock.Sp2, rawblock.Sp3, rawblock.Sp2, rawblock.Sp3,
			rawblock.NewH4("INCOMING CONNECTION", rawblock.ColorWhite)))

		details := rawblock.GapVBox(rawblock.Sp2,
			kvRow("PEER ID", rawblock.NewMono(req.PeerID, rawblock.ColorBlack)),
			kvRow("LABEL", rawblock.NewBody(nameText, rawblock.ColorBlack)),
			kvRow("KEY", rawblock.NewMono(strings.ToUpper(string(req.Algorithm)), rawblock.ColorBlack)),
			kvRow("VIRTUAL IP", rawblock.NewMono(req.VirtualIP.String(), rawblock.ColorBlack)),
			kvRow("DTLS SHA-256", rawblock.NewMono(fpShort, rawblock.ColorBlack)),
		)

		allowBtn := rawblock.NewButton("ALLOW", rawblock.ButtonPrimary, rawblock.ButtonMedium, func() {
			c.RespondIncoming(peer.ConsentAllow)
		})
		denyBtn := rawblock.NewButton("DENY", rawblock.ButtonSecondary, rawblock.ButtonMedium, func() {
			c.RespondIncoming(peer.ConsentDeny)
		})
		blockBtn := rawblock.NewButton("BLACKLIST", rawblock.ButtonDestructive, rawblock.ButtonMedium, func() {
			c.RespondIncoming(peer.ConsentBlacklist)
		})

		modalBody := rawblock.GapVBox(rawblock.Sp3,
			header,
			details,
			rawblock.NewDivider(rawblock.BorderThick),
			rawblock.GapHBox(rawblock.Sp2, allowBtn, denyBtn, blockBtn),
		)
		modalCard := rawblock.NewCard(modalBody, rawblock.CardElevated)

		pop := widget.NewModalPopUp(modalCard, c.window.Canvas())
		pc.popup = pop
		pop.Show()
	})

	c.mu.Lock()
	c.activeConsent = pc
	c.mu.Unlock()

	select {
	case dec := <-pc.respCh:
		return dec
	case <-ctx.Done():
		c.RespondIncoming(peer.ConsentDeny)
		return peer.ConsentDeny
	}
}

func (c *Controller) refreshLists() {
	c.mu.Lock()
	client := c.client
	router := c.router
	peers := append([]peer.DiscoveredPeer(nil), c.peers...)
	var routes []tun.RouteInfo
	if router != nil {
		routes = router.Routes()
	}
	var bl []string
	if client != nil {
		bl = client.BlacklistedPeers()
	}
	c.routes = routes
	c.blacklisted = bl
	c.mu.Unlock()

	c.doUI(func() {
		// Discovered peers list (3px black dividers, 12px vertical padding, zero icons).
		c.PeersBox.Objects = nil
		if len(peers) == 0 {
			c.PeersBox.Add(emptyListRow("NO PEERS"))
		} else {
			for i, dp := range peers {
				pid := dp.PeerID
				meta := rawblock.GapVBox(rawblock.Sp1,
					rawblock.NewMono(dp.VirtualIP.String(), rawblock.ColorBlack),
					rawblock.NewSmall(fmt.Sprintf("%s  //  %s", truncateLabel(nonEmptyLabel(dp.DisplayName), 14), shortID8(pid)), rawblock.ColorContentSecondary),
				)
				connBtn := rawblock.NewButton("CONNECT", rawblock.ButtonPrimary, rawblock.ButtonSmall, func() { go c.connectPeerAction(pid) })
				blockBtn := rawblock.NewButton("BLACKLIST", rawblock.ButtonDestructive, rawblock.ButtonSmall, func() { go c.blacklistPeerAction(pid) })
				row := rawblock.InsetBox(12, 0, 12, 0,
					container.NewBorder(nil, nil, nil, rawblock.GapHBox(rawblock.Sp2, connBtn, blockBtn), meta))
				c.PeersBox.Add(row)
				if i < len(peers)-1 {
					c.PeersBox.Add(rawblock.NewDivider(rawblock.BorderThick))
				}
			}
		}
		c.PeersBox.Refresh()

		// Active TUN tunnels list.
		c.TunnelsBox.Objects = nil
		if len(routes) == 0 {
			c.TunnelsBox.Add(emptyListRow("NO ACTIVE TUNNELS"))
		} else {
			for i, rt := range routes {
				pid := rt.PeerID
				meta := rawblock.GapVBox(rawblock.Sp1,
					rawblock.GapHBox(rawblock.Sp2,
						rawblock.NewStatusChip("ACTIVE", rawblock.ChipActive),
						rawblock.NewMono(rt.VirtualIP.String(), rawblock.ColorBlack),
					),
					rawblock.NewSmall(shortID(pid), rawblock.ColorContentSecondary),
				)
				discBtn := rawblock.NewButton("DISCONNECT", rawblock.ButtonSecondary, rawblock.ButtonSmall, func() {
					go func() {
						if client != nil {
							for _, s := range client.ActiveSessions() {
								if s.RemotePeerID() == pid {
									_ = s.Close()
								}
							}
						}
					}()
				})
				blockBtn := rawblock.NewButton("BLACKLIST", rawblock.ButtonDestructive, rawblock.ButtonSmall, func() { go c.blacklistPeerAction(pid) })
				row := rawblock.InsetBox(12, 0, 12, 0,
					container.NewBorder(nil, nil, nil, rawblock.GapHBox(rawblock.Sp2, discBtn, blockBtn), meta))
				c.TunnelsBox.Add(row)
				if i < len(routes)-1 {
					c.TunnelsBox.Add(rawblock.NewDivider(rawblock.BorderThick))
				}
			}
		}
		c.TunnelsBox.Refresh()

		// Blacklist tab.
		c.BlacklistBox.Objects = nil
		if len(bl) == 0 {
			c.BlacklistBox.Add(emptyListRow("EMPTY"))
		} else {
			for i, pid := range bl {
				target := pid
				meta := rawblock.GapHBox(rawblock.Sp2,
					rawblock.NewStatusChip("BLOCKED", rawblock.ChipError),
					rawblock.NewMono(shortID(target), rawblock.ColorBlack),
				)
				remBtn := rawblock.NewButton("REMOVE", rawblock.ButtonSecondary, rawblock.ButtonSmall, func() { go c.unblacklistPeerAction(target) })
				row := rawblock.InsetBox(12, 0, 12, 0,
					container.NewBorder(nil, nil, nil, remBtn, meta))
				c.BlacklistBox.Add(row)
				if i < len(bl)-1 {
					c.BlacklistBox.Add(rawblock.NewDivider(rawblock.BorderThick))
				}
			}
		}
		c.BlacklistBox.Refresh()
	})
}

func nonEmptyLabel(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(unlabeled)"
	}
	return s
}

func shortID(peerID string) string {
	if len(peerID) <= 12 {
		return peerID
	}
	return peerID[:12]
}

func shortID8(peerID string) string {
	if len(peerID) <= 8 {
		return peerID
	}
	return peerID[:8]
}

func truncateLabel(s string, maxLen int) string {
	rs := []rune(s)
	if len(rs) <= maxLen {
		return s
	}
	return string(rs[:maxLen-1]) + "…"
}
