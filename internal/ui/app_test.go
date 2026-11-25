package ui_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	fyneTest "fyne.io/fyne/v2/test"

	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/internal/ui"
	"lighthouse-in-snoo/internal/ui/rawblock"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/peer"
	"lighthouse-in-snoo/pkg/tun"
)

func buildIPv4(src, dst netip.Addr, body []byte) []byte {
	s4 := src.As4()
	d4 := dst.As4()
	pkt := make([]byte, 20+len(body))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	copy(pkt[20:], body)
	return pkt
}

func makeUITestTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}},
		&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
}

func TestFyneControllerBindBroadcastConsentAllowDenyBlacklist(t *testing.T) {
	srvTLS, cliTLS := makeUITestTLS(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "wss://" + ln.Addr().String()
	srv, err := hub.New(&hub.Config{
		HTTPSListener:   ln,
		TLSConfig:       srvTLS,
		HubOrigin:       origin,
		EnableSTUN:      true,
		STUNSListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	wsURL := origin + "/v1/signal"
	stunsURI := "stuns:" + srv.STUNSAddr().String()
	kpA, _ := identity.GenerateKeyPair()
	kpB, _ := identity.GenerateKeyPair()

	devA := tun.NewMemoryDevice("lhA", tun.DefaultMTU)
	devB := tun.NewMemoryDevice("lhB", tun.DefaultMTU)

	appA := fyneTest.NewTempApp(t)
	ctrlA, err := ui.NewController(appA, ui.Options{
		KeyPair:         kpA,
		BlacklistPath:   filepath.Join(t.TempDir(), "blA.json"),
		HubURL:          wsURL,
		STUNServerURI:   stunsURI,
		TLSConfig:       cliTLS,
		IncludeLoopback: true,
		InterfaceName:   "lhA",
		OpenDevice:      func(_ netip.Addr) (tun.Device, error) { return devA, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctrlA.Disconnect()

	appB := fyneTest.NewTempApp(t)
	ctrlB, err := ui.NewController(appB, ui.Options{
		KeyPair:         kpB,
		BlacklistPath:   filepath.Join(t.TempDir(), "blB.json"),
		HubURL:          wsURL,
		STUNServerURI:   stunsURI,
		TLSConfig:       cliTLS,
		IncludeLoopback: true,
		InterfaceName:   "lhB",
		OpenDevice:      func(_ netip.Addr) (tun.Device, error) { return devB, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctrlB.Disconnect()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := ctrlA.ConnectAndBind(ctx); err != nil {
		t.Fatalf("ctrlA.ConnectAndBind: %v", err)
	}
	if err := ctrlB.ConnectAndBind(ctx); err != nil {
		t.Fatalf("ctrlB.ConnectAndBind: %v", err)
	}
	if ctrlA.Router() == nil || ctrlB.Router() == nil {
		t.Fatal("expected TUN routers bound on both controllers")
	}

	// Peer B chooses to broadcast on passphrase "ui-room"; Peer A chooses to listen on "ui-room".
	chID, err := ctrlB.Client().SetBroadcast(ctx, true, "ui-room", "Bob-Desktop")
	if err != nil {
		t.Fatalf("B SetBroadcast: %v", err)
	}
	if _, err := ctrlA.Client().JoinChannel(ctx, "ui-room"); err != nil {
		t.Fatalf("A JoinChannel: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var discovered []peer.DiscoveredPeer
	for time.Now().Before(deadline) {
		discovered = ctrlA.Client().DiscoveredPeers(chID)
		if len(discovered) == 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if len(discovered) != 1 || discovered[0].PeerID != kpB.PeerID || discovered[0].DisplayName != "Bob-Desktop" {
		t.Fatalf("unexpected discovered peers on A: %+v", discovered)
	}

	// 1. Explicit DENY on incoming modal prompt.
	denyErrCh := make(chan error, 1)
	go func() {
		_, err := ctrlA.Client().Connect(ctx, kpB.PeerID)
		denyErrCh <- err
	}()

	var req peer.IncomingRequest
	waitReq := func() peer.IncomingRequest {
		t.Helper()
		dl := time.Now().Add(5 * time.Second)
		for time.Now().Before(dl) {
			if r, ok := ctrlB.PendingRequest(); ok {
				return r
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("timed out waiting for incoming consent prompt on controller B")
		return peer.IncomingRequest{}
	}
	req = waitReq()
	if req.PeerID != kpA.PeerID || req.VirtualIP != ctrlA.Client().VirtualIP() || len(req.DTLSFingerprints) == 0 {
		t.Fatalf("unexpected incoming request metadata: %+v", req)
	}
	if !ctrlB.RespondIncoming(peer.ConsentDeny) {
		t.Fatal("RespondIncoming(Deny) returned false")
	}
	if err := <-denyErrCh; !errors.Is(err, peer.ErrUserDenied) {
		t.Fatalf("expected ErrUserDenied after Deny, got %v", err)
	}
	if len(ctrlB.Router().Routes()) != 0 {
		t.Fatalf("expected 0 TUN routes after Deny, got %+v", ctrlB.Router().Routes())
	}

	// 2. Explicit ALLOW -> TUN routes installed on both sides & IPv4 traffic flows!
	type connectResult struct {
		sess *peer.Session
		err  error
	}
	allowResCh := make(chan connectResult, 1)
	go func() {
		s, err := ctrlA.Client().Connect(ctx, kpB.PeerID)
		allowResCh <- connectResult{sess: s, err: err}
	}()
	_ = waitReq()
	if !ctrlB.RespondIncoming(peer.ConsentAllow) {
		t.Fatal("RespondIncoming(Allow) returned false")
	}
	allowRes := <-allowResCh
	if allowRes.err != nil {
		t.Fatalf("Connect after Allow failed: %v", allowRes.err)
	}
	sessA := allowRes.sess

	// Wait until both routers attach the active session route via OnSession callback.
	dl := time.Now().Add(3 * time.Second)
	for time.Now().Before(dl) {
		if len(ctrlA.Router().Routes()) == 1 && len(ctrlB.Router().Routes()) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(ctrlA.Router().Routes()) != 1 || len(ctrlB.Router().Routes()) != 1 {
		t.Fatalf("expected active TUN routes on both A and B, got A=%d B=%d",
			len(ctrlA.Router().Routes()), len(ctrlB.Router().Routes()))
	}

	pkt := buildIPv4(ctrlA.Client().VirtualIP(), ctrlB.Client().VirtualIP(), []byte("fyne-tun-ip-packet"))
	if err := devA.InjectOutbound(ctx, pkt); err != nil {
		t.Fatal(err)
	}
	got, err := devB.ReadInbound(ctx)
	if err != nil {
		t.Fatalf("timeout waiting for TUN packet on B: %v", err)
	}
	if !bytes.Equal(got, pkt) {
		t.Fatal("TUN packet mismatch across Fyne-bound tunnel")
	}

	// 3. Explicit BLACKLIST -> terminates tunnel and auto-rejects subsequent connection without prompting!
	if err := ctrlB.Client().Blacklist(kpA.PeerID); err != nil {
		t.Fatalf("Blacklist: %v", err)
	}
	if !ctrlB.Client().IsBlacklisted(kpA.PeerID) {
		t.Fatal("expected A to be blacklisted on B")
	}
	select {
	case <-sessA.Closed():
	case <-time.After(3 * time.Second):
		t.Fatal("expected active session on A to close after B blacklisted A")
	}
	if _, err := ctrlA.Client().Connect(ctx, kpB.PeerID); !errors.Is(err, peer.ErrPeerBlacklisted) {
		t.Fatalf("expected ErrPeerBlacklisted on reconnect after blacklist, got %v", err)
	}
	if _, pending := ctrlB.PendingRequest(); pending {
		t.Fatal("blacklisted peer MUST NOT trigger consent prompt")
	}
	if err := ctrlB.Client().Unblacklist(kpA.PeerID); err != nil {
		t.Fatalf("Unblacklist: %v", err)
	}
	if ctrlB.Client().IsBlacklisted(kpA.PeerID) {
		t.Fatal("expected A removed from blacklist")
	}
}

func TestFyneControllerCustomCIDRAndCopyableAlertModals(t *testing.T) {
	srvTLS, cliTLS := makeUITestTLS(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "wss://" + ln.Addr().String()
	srv, err := hub.New(&hub.Config{
		HTTPSListener:   ln,
		TLSConfig:       srvTLS,
		HubOrigin:       origin,
		EnableSTUN:      true,
		STUNSListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	wsURL := origin + "/v1/signal"
	stunsURI := "stuns:" + srv.STUNSAddr().String()
	kpA, _ := identity.GenerateKeyPair()
	kpB, _ := identity.GenerateKeyPair()
	customCIDR := netip.MustParsePrefix("10.99.0.0/24")

	appA := fyneTest.NewTempApp(t)
	ctrlA, err := ui.NewController(appA, ui.Options{
		KeyPair:         kpA,
		BlacklistPath:   filepath.Join(t.TempDir(), "blA.json"),
		HubURL:          wsURL,
		STUNServerURI:   stunsURI,
		TLSConfig:       cliTLS,
		IncludeLoopback: true,
		InterfaceName:   "lhA",
		OpenDevice:      func(_ netip.Addr) (tun.Device, error) { return tun.NewMemoryDevice("lhA", tun.DefaultMTU), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctrlA.Disconnect()

	// Default CIDR must be 10.88.0.0/16.
	if got := ctrlA.VirtualCIDR(); got != netip.MustParsePrefix("10.88.0.0/16") {
		t.Fatalf("default VirtualCIDR = %s; want 10.88.0.0/16", got)
	}

	waitAlert := func(c *ui.Controller) (rawblock.AlertSeverity, string, string) {
		t.Helper()
		dl := time.Now().Add(2 * time.Second)
		for time.Now().Before(dl) {
			if sev, title, detail, ok := c.ActiveAlert(); ok {
				return sev, title, detail
			}
			time.Sleep(15 * time.Millisecond)
		}
		t.Fatal("timed out waiting for alert modal")
		return 0, "", ""
	}

	// Warning modal on offline Join action.
	fyneTest.Tap(ctrlA.JoinBtn)
	sev, title, _ := waitAlert(ctrlA)
	if sev != rawblock.AlertWarning || title != "NOT CONNECTED" {
		t.Fatalf("expected WARNING/NOT CONNECTED modal, got %v/%q", sev, title)
	}
	ctrlA.DismissAlert()

	// Error modal on invalid IP CIDR when tapping Bind & Connect.
	ctrlA.CIDRInput.SetText("not-a-valid-cidr")
	fyneTest.Tap(ctrlA.ConnectHubBtn)
	sev, title, detail := waitAlert(ctrlA)
	if sev != rawblock.AlertError || title != "BIND & CONNECT FAILED" || detail == "" {
		t.Fatalf("expected ERROR modal for invalid CIDR, got %v/%q/%q", sev, title, detail)
	}
	ctrlA.DismissAlert()

	// Configure custom 10.99.0.0/24 CIDR via UI input on A and Options on B, then route IPv4 traffic.
	devA := tun.NewMemoryDevice("lhA", tun.DefaultMTU)
	devB := tun.NewMemoryDevice("lhB", tun.DefaultMTU)

	appA2 := fyneTest.NewTempApp(t)
	ctrlA2, err := ui.NewController(appA2, ui.Options{
		KeyPair:         kpA,
		BlacklistPath:   filepath.Join(t.TempDir(), "blA2.json"),
		HubURL:          wsURL,
		STUNServerURI:   stunsURI,
		TLSConfig:       cliTLS,
		IncludeLoopback: true,
		InterfaceName:   "lhA",
		OpenDevice:      func(_ netip.Addr) (tun.Device, error) { return devA, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctrlA2.Disconnect()
	ctrlA2.CIDRInput.SetText(customCIDR.String())

	appB := fyneTest.NewTempApp(t)
	ctrlB, err := ui.NewController(appB, ui.Options{
		KeyPair:         kpB,
		BlacklistPath:   filepath.Join(t.TempDir(), "blB.json"),
		HubURL:          wsURL,
		STUNServerURI:   stunsURI,
		TLSConfig:       cliTLS,
		IncludeLoopback: true,
		InterfaceName:   "lhB",
		VirtualCIDR:     customCIDR,
		OpenDevice:      func(_ netip.Addr) (tun.Device, error) { return devB, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctrlB.Disconnect()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := ctrlA2.ConnectAndBind(ctx); err != nil {
		t.Fatalf("ctrlA2.ConnectAndBind: %v", err)
	}
	if err := ctrlB.ConnectAndBind(ctx); err != nil {
		t.Fatalf("ctrlB.ConnectAndBind: %v", err)
	}
	if !customCIDR.Contains(ctrlA2.Client().VirtualIP()) || !customCIDR.Contains(ctrlB.Client().VirtualIP()) {
		t.Fatalf("expected virtual IPs in %s, got A=%s B=%s", customCIDR, ctrlA2.Client().VirtualIP(), ctrlB.Client().VirtualIP())
	}

	errCh := make(chan error, 1)
	go func() {
		_, cErr := ctrlA2.Client().Connect(ctx, kpB.PeerID)
		errCh <- cErr
	}()
	dl := time.Now().Add(5 * time.Second)
	for time.Now().Before(dl) {
		if _, ok := ctrlB.PendingRequest(); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ctrlB.RespondIncoming(peer.ConsentAllow) {
		t.Fatal("RespondIncoming(Allow) failed")
	}
	if cErr := <-errCh; cErr != nil {
		t.Fatalf("Connect with custom CIDR failed: %v", cErr)
	}

	dl = time.Now().Add(3 * time.Second)
	for time.Now().Before(dl) {
		if len(ctrlA2.Router().Routes()) == 1 && len(ctrlB.Router().Routes()) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	pkt := buildIPv4(ctrlA2.Client().VirtualIP(), ctrlB.Client().VirtualIP(), []byte("custom-cidr-10-99"))
	if err := devA.InjectOutbound(ctx, pkt); err != nil {
		t.Fatal(err)
	}
	got, err := devB.ReadInbound(ctx)
	if err != nil {
		t.Fatalf("ReadInbound B on custom CIDR: %v", err)
	}
	if !bytes.Equal(got, pkt) {
		t.Fatal("TUN packet mismatch on custom CIDR")
	}
}
