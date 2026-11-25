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
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

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
	dlg    dialog.Dialog
}

// Controller binds a Fyne desktop UI to a Lighthouse peer Client and OS TUN Router.
// All incoming connections require explicit Allow / Deny / Blacklist user action.
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
	peers            []peer.DiscoveredPeer
	routes           []tun.RouteInfo
	blacklisted      []string
	consentPrompting bool
	activeConsent    *pendingConsent

	// Exposed widgets for user interaction and deterministic Fyne headless tests.
	StatusLabel     *widget.Label
	PeerIDLabel     *widget.Label
	VirtualIPLabel  *widget.Label
	InterfaceLabel  *widget.Label
	HubURLEntry     *widget.Entry
	HubPassEntry    *widget.Entry
	IfNameEntry     *widget.Entry
	TCPOnlyCheck    *widget.Check
	ConnectHubBtn   *widget.Button
	PassphraseEntry *widget.Entry
	DisplayEntry    *widget.Entry
	JoinBtn         *widget.Button
	BroadcastCheck  *widget.Check
	DirectPeerEntry *widget.Entry
	DirectConnBtn   *widget.Button
	PeersBox        *fyne.Container
	TunnelsBox      *fyne.Container
	BlacklistBox    *fyne.Container
}

// NewController constructs the Fyne window and wires controls for TUN binding,
// passphrase-scoped broadcasting, peer connection, incoming consent, and blacklisting.
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

	w := a.NewWindow("Lighthouse")
	w.Resize(fyne.NewSize(760, 560))

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
	if pc.dlg != nil {
		c.doUI(func() {
			pc.dlg.Hide()
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
	c.StatusLabel = widget.NewLabel("Disconnected")
	c.PeerIDLabel = widget.NewLabel(c.opts.KeyPair.PeerID)
	c.VirtualIPLabel = widget.NewLabel(c.vip.String())
	c.InterfaceLabel = widget.NewLabel("Unbound")

	copyIDBtn := widget.NewButton("Copy ID", func() {
		c.app.Clipboard().SetContent(c.opts.KeyPair.PeerID)
	})

	c.HubURLEntry = widget.NewEntry()
	c.HubURLEntry.SetText(c.opts.HubURL)
	c.HubURLEntry.SetPlaceHolder("wss://hub.example.com/v1/signal")

	c.HubPassEntry = widget.NewPasswordEntry()
	c.HubPassEntry.SetText(c.opts.HubPassphrase)
	c.HubPassEntry.SetPlaceHolder("Optional")

	c.IfNameEntry = widget.NewEntry()
	c.IfNameEntry.SetText(c.opts.InterfaceName)

	c.TCPOnlyCheck = widget.NewCheck("TCP Only", nil)
	c.TCPOnlyCheck.SetChecked(c.opts.TCPOnly)

	c.ConnectHubBtn = widget.NewButton("Bind & Connect", func() {
		go c.toggleConnection()
	})

	c.PassphraseEntry = widget.NewPasswordEntry()
	c.PassphraseEntry.SetPlaceHolder("Shared passphrase")

	c.DisplayEntry = widget.NewEntry()
	c.DisplayEntry.SetPlaceHolder("Peer label")

	c.JoinBtn = widget.NewButton("Join", func() {
		go c.joinChannelAction()
	})

	c.BroadcastCheck = widget.NewCheck("Broadcast", func(enabled bool) {
		go c.broadcastToggleAction(enabled)
	})

	c.DirectPeerEntry = widget.NewEntry()
	c.DirectPeerEntry.SetPlaceHolder("Peer ID")
	c.DirectConnBtn = widget.NewButton("Connect", func() {
		target := strings.TrimSpace(c.DirectPeerEntry.Text)
		if target != "" {
			go c.connectPeerAction(target)
		}
	})

	c.PeersBox = container.NewVBox(widget.NewLabel("No peers"))
	c.TunnelsBox = container.NewVBox(widget.NewLabel("No active tunnels"))
	c.BlacklistBox = container.NewVBox(widget.NewLabel("Empty"))

	identityCard := widget.NewForm(
		widget.NewFormItem("Peer ID", container.NewBorder(nil, nil, nil, copyIDBtn, c.PeerIDLabel)),
		widget.NewFormItem("Virtual IP", c.VirtualIPLabel),
		widget.NewFormItem("Interface", c.InterfaceLabel),
		widget.NewFormItem("Status", c.StatusLabel),
	)

	hubForm := widget.NewForm(
		widget.NewFormItem("Hub", c.HubURLEntry),
		widget.NewFormItem("Hub Passphrase", c.HubPassEntry),
		widget.NewFormItem("TUN Name", c.IfNameEntry),
	)
	hubBar := container.NewVBox(
		hubForm,
		container.NewHBox(c.TCPOnlyCheck, c.ConnectHubBtn),
	)

	discoverControls := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Passphrase", c.PassphraseEntry),
			widget.NewFormItem("Label", c.DisplayEntry),
		),
		container.NewHBox(c.JoinBtn, c.BroadcastCheck),
		widget.NewSeparator(),
		container.NewBorder(nil, nil, widget.NewLabel("Direct"), c.DirectConnBtn, c.DirectPeerEntry),
		widget.NewSeparator(),
		container.NewVScroll(c.PeersBox),
	)

	tabs := container.NewAppTabs(
		container.NewTabItem("Peers", discoverControls),
		container.NewTabItem("Tunnels", container.NewVScroll(c.TunnelsBox)),
		container.NewTabItem("Blacklist", container.NewVScroll(c.BlacklistBox)),
	)

	root := container.NewBorder(
		container.NewVBox(identityCard, widget.NewSeparator(), hubBar, widget.NewSeparator()),
		nil, nil, nil,
		tabs,
	)
	c.window.SetContent(root)
}

func (c *Controller) setStatus(msg string) {
	c.doUI(func() {
		c.StatusLabel.SetText(msg)
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
		c.setStatus("Error: " + err.Error())
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

	c.doUI(func() {
		c.InterfaceLabel.SetText(fmt.Sprintf("%s (%s/%d)", dev.Name(), c.vip.String(), tun.DefaultSubnetPrefixBits))
		c.StatusLabel.SetText("Connected")
		c.ConnectHubBtn.SetText("Disconnect")
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
		c.BroadcastCheck.SetChecked(false)
		c.InterfaceLabel.SetText("Unbound")
		c.StatusLabel.SetText("Disconnected")
		c.ConnectHubBtn.SetText("Bind & Connect")
	})
	c.refreshLists()
}

func (c *Controller) joinChannelAction() {
	var pass string
	c.doUIWait(func() {
		pass = c.PassphraseEntry.Text
	})
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil {
		c.setStatus("Connect to hub first")
		return
	}
	chID, err := client.JoinChannel(context.Background(), pass)
	if err != nil {
		c.setStatus("Join failed: " + err.Error())
		return
	}
	c.mu.Lock()
	c.joinedPass = pass
	c.joinedChanID = chID
	c.mu.Unlock()
	c.setStatus("Listening on channel")
}

func (c *Controller) broadcastToggleAction(enabled bool) {
	var pass, label string
	c.doUIWait(func() {
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
			c.doUI(func() { c.BroadcastCheck.SetChecked(false) })
			c.setStatus("Connect to hub first")
		}
		return
	}
	if _, err := client.SetBroadcast(context.Background(), enabled, pass, label); err != nil {
		c.doUI(func() { c.BroadcastCheck.SetChecked(!enabled) })
		c.setStatus("Broadcast failed: " + err.Error())
		return
	}
	c.mu.Lock()
	c.broadcasting = enabled
	c.mu.Unlock()
	if enabled {
		c.setStatus("Broadcasting")
	} else {
		c.setStatus("Broadcast stopped")
	}
}

func (c *Controller) connectPeerAction(targetPeerID string) {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil {
		c.setStatus("Connect to hub first")
		return
	}
	c.setStatus("Connecting " + shortID(targetPeerID))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.Connect(ctx, targetPeerID); err != nil {
		c.setStatus("Connect failed: " + err.Error())
		return
	}
	c.setStatus("Tunnel active: " + shortID(targetPeerID))
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
		c.setStatus("Blacklist failed: " + err.Error())
		return
	}
	if router != nil {
		router.DetachPeer(peerID)
	}
	c.setStatus("Blacklisted " + shortID(peerID))
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
	c.setStatus("Removed " + shortID(peerID))
	c.refreshLists()
}

// AuthorizeIncoming implements peer.ConsentHandler with an explicit Fyne modal prompt.
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
		if len(fpShort) > 23 {
			fpShort = fpShort[:23] + "..."
		}
	}
	nameText := req.DisplayName
	if nameText == "" {
		nameText = "(unlabeled)"
	}

	c.doUIWait(func() {
		info := widget.NewForm(
			widget.NewFormItem("Peer", widget.NewLabel(req.PeerID)),
			widget.NewFormItem("Label", widget.NewLabel(nameText)),
			widget.NewFormItem("Key", widget.NewLabel(string(req.Algorithm))),
			widget.NewFormItem("Virtual IP", widget.NewLabel(req.VirtualIP.String())),
			widget.NewFormItem("DTLS SHA-256", widget.NewLabel(fpShort)),
		)
		allowBtn := widget.NewButton("Allow", func() {
			c.RespondIncoming(peer.ConsentAllow)
		})
		allowBtn.Importance = widget.HighImportance
		denyBtn := widget.NewButton("Deny", func() {
			c.RespondIncoming(peer.ConsentDeny)
		})
		blockBtn := widget.NewButton("Blacklist", func() {
			c.RespondIncoming(peer.ConsentBlacklist)
		})
		blockBtn.Importance = widget.DangerImportance

		body := container.NewVBox(info, container.NewHBox(allowBtn, denyBtn, blockBtn))
		dlg := dialog.NewCustomWithoutButtons("Incoming Connection", body, c.window)
		pc.dlg = dlg
		dlg.Show()
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
		// Discovered peers list.
		c.PeersBox.Objects = nil
		if len(peers) == 0 {
			c.PeersBox.Add(widget.NewLabel("No peers"))
		} else {
			for _, dp := range peers {
				pid := dp.PeerID
				label := fmt.Sprintf("%s  %s  (%s)", dp.VirtualIP.String(), shortID(pid), dp.DisplayName)
				if dp.DisplayName == "" {
					label = fmt.Sprintf("%s  %s", dp.VirtualIP.String(), shortID(pid))
				}
				connBtn := widget.NewButton("Connect", func() { go c.connectPeerAction(pid) })
				blockBtn := widget.NewButton("Blacklist", func() { go c.blacklistPeerAction(pid) })
				c.PeersBox.Add(container.NewBorder(nil, nil, nil, container.NewHBox(connBtn, blockBtn), widget.NewLabel(label)))
			}
		}
		c.PeersBox.Refresh()

		// Active TUN tunnels list.
		c.TunnelsBox.Objects = nil
		if len(routes) == 0 {
			c.TunnelsBox.Add(widget.NewLabel("No active tunnels"))
		} else {
			for _, rt := range routes {
				pid := rt.PeerID
				rowLabel := fmt.Sprintf("%s  %s", rt.VirtualIP.String(), shortID(pid))
				discBtn := widget.NewButton("Disconnect", func() {
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
				blockBtn := widget.NewButton("Blacklist", func() { go c.blacklistPeerAction(pid) })
				c.TunnelsBox.Add(container.NewBorder(nil, nil, nil, container.NewHBox(discBtn, blockBtn), widget.NewLabel(rowLabel)))
			}
		}
		c.TunnelsBox.Refresh()

		// Blacklist tab.
		c.BlacklistBox.Objects = nil
		if len(bl) == 0 {
			c.BlacklistBox.Add(widget.NewLabel("Empty"))
		} else {
			for _, pid := range bl {
				target := pid
				remBtn := widget.NewButton("Remove", func() { go c.unblacklistPeerAction(target) })
				c.BlacklistBox.Add(container.NewBorder(nil, nil, nil, remBtn, widget.NewLabel(target)))
			}
		}
		c.BlacklistBox.Refresh()
	})
}

func shortID(peerID string) string {
	if len(peerID) <= 12 {
		return peerID
	}
	return peerID[:12]
}
