package hub_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/protocol"
)

func makeCert(t *testing.T) (srvTLS, cliTLS *tls.Config) {
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

	srvTLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}},
	}
	cliTLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	return srvTLS, cliTLS
}

func dialAndRegister(
	t *testing.T,
	ctx context.Context,
	hc *http.Client,
	wsURL, origin, passphrase string,
	kp *identity.KeyPair,
) (*websocket.Conn, protocol.RegisteredMessage) {
	t.Helper()
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, chalRaw, err := c.Read(ctx)
	if err != nil {
		_ = c.CloseNow()
		t.Fatalf("read challenge: %v", err)
	}
	var chal protocol.ChallengeMessage
	if err := json.Unmarshal(chalRaw, &chal); err != nil {
		_ = c.CloseNow()
		t.Fatalf("parse challenge: %v", err)
	}
	proof, err := kp.SignRegistrationChallenge(chal.Challenge, origin)
	if err != nil {
		_ = c.CloseNow()
		t.Fatal(err)
	}
	hubAuth := ""
	if passphrase != "" {
		hubAuth, err = identity.SignHubPassphraseProof(passphrase, chal.Challenge, origin, kp.PeerID)
		if err != nil {
			_ = c.CloseNow()
			t.Fatal(err)
		}
	}
	regRaw, _ := json.Marshal(protocol.RegisterMessage{
		V:         protocol.Version,
		Type:      protocol.TypeRegister,
		PeerID:    kp.PeerID,
		PublicKey: identity.EncodePublicKey(kp.PublicKey),
		HubOrigin: origin,
		Challenge: chal.Challenge,
		Proof:     proof,
		HubAuth:   hubAuth,
	})
	if err := c.Write(ctx, websocket.MessageText, regRaw); err != nil {
		_ = c.CloseNow()
		t.Fatal(err)
	}
	_, respRaw, err := c.Read(ctx)
	if err != nil {
		_ = c.CloseNow()
		t.Fatalf("read register response: %v", err)
	}
	var reg protocol.RegisteredMessage
	if err := json.Unmarshal(respRaw, &reg); err != nil || reg.Type != protocol.TypeRegistered {
		_ = c.CloseNow()
		t.Fatalf("expected registered, got %s", string(respRaw))
	}
	return c, reg
}

func TestHubPassphraseGateUniversalRelayAndBroadcastIsolation(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS := makeCert(t)
	kpA, _ := identity.GenerateKeyPair()
	kpB, _ := identity.GenerateKeyPair()
	kpC, _ := identity.GenerateKeyPair()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "wss://" + ln.Addr().String()
	const hubSecret = "offline-hub-passphrase"
	srv, err := hub.New(&hub.Config{
		HTTPSListener:      ln,
		TLSConfig:          srvTLS,
		HubOrigin:          origin,
		Passphrase:         hubSecret,
		EnableSTUN:         true,
		EnableTURN:         true,
		STUNSListenAddr:    "127.0.0.1:0",
		TURNRelayBindAddr:  "127.0.0.1",
		MaxSessionsPerPeer: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if !srv.PassphraseRequired() || !srv.TURNActive() {
		t.Fatalf("expected passphrase-gated hub with universal relay active")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cliTLS}}
	wsURL := origin + "/v1/signal"

	// 1. Sending channel_join before register MUST fail with unauthenticated.
	cUnauth, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		t.Fatal(err)
	}
	_, chalRawUnauth, _ := cUnauth.Read(ctx)
	var chalUnauth protocol.ChallengeMessage
	_ = json.Unmarshal(chalRawUnauth, &chalUnauth)
	if !chalUnauth.PassphraseRequired {
		t.Fatal("expected challenge to advertise passphrase_required=true")
	}
	_ = cUnauth.Write(ctx, websocket.MessageText, []byte(`{"v":2,"type":"channel_join","channel_id":"0123456789abcdef0123456789abcdef0123456789a"}`))
	_, rawErr, _ := cUnauth.Read(ctx)
	var em protocol.ErrorMessage
	_ = json.Unmarshal(rawErr, &em)
	if em.Code != protocol.ErrCodeUnauthenticated {
		t.Fatalf("expected unauthenticated error, got %+v", em)
	}
	_ = cUnauth.CloseNow()

	// 2. Registering with wrong hub passphrase MUST be rejected.
	cBadPass, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		t.Fatal(err)
	}
	_, chalRawBad, _ := cBadPass.Read(ctx)
	var chalBad protocol.ChallengeMessage
	_ = json.Unmarshal(chalRawBad, &chalBad)
	proofBad, _ := kpA.SignRegistrationChallenge(chalBad.Challenge, origin)
	wrongAuth, _ := identity.SignHubPassphraseProof("wrong-passphrase", chalBad.Challenge, origin, kpA.PeerID)
	regBad, _ := json.Marshal(protocol.RegisterMessage{
		V: protocol.Version, Type: protocol.TypeRegister, PeerID: kpA.PeerID,
		PublicKey: identity.EncodePublicKey(kpA.PublicKey), HubOrigin: origin,
		Challenge: chalBad.Challenge, Proof: proofBad, HubAuth: wrongAuth,
	})
	_ = cBadPass.Write(ctx, websocket.MessageText, regBad)
	_, badRespRaw, _ := cBadPass.Read(ctx)
	var badErr protocol.ErrorMessage
	_ = json.Unmarshal(badRespRaw, &badErr)
	if badErr.Code != protocol.ErrCodeAuthFailed {
		t.Fatalf("expected auth_failed, got %+v", badErr)
	}
	_ = cBadPass.CloseNow()

	// 3. Valid registration succeeds, assigns default 10.88.0.0/16 IP, and mints universal TURNS relay credentials.
	cA, regA := dialAndRegister(t, ctx, hc, wsURL, origin, hubSecret, kpA)
	defer cA.CloseNow()
	if regA.VirtualCIDR != identity.DefaultVirtualCIDRString {
		t.Fatalf("expected default virtual_cidr %q, got %q", identity.DefaultVirtualCIDRString, regA.VirtualCIDR)
	}
	wantIPA, _ := identity.VirtualIPv4FromPeerID(kpA.PeerID)
	if regA.AssignedIP != wantIPA.String() {
		t.Fatalf("expected assigned_ip %q, got %q", wantIPA.String(), regA.AssignedIP)
	}
	if regA.Relay == nil || len(regA.Relay.URIs) == 0 || !strings.HasPrefix(regA.Relay.URIs[0], "turns:") || regA.Relay.Username == "" || regA.Relay.Credential == "" {
		t.Fatalf("expected auto-minted universal TURNS relay info, got %+v", regA.Relay)
	}

	// 4. Replaying an old challenge on a second connection MUST fail with challenge_invalid.
	cReuse, _, _ := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc})
	_, _, _ = cReuse.Read(ctx)
	_ = cReuse.Write(ctx, websocket.MessageText, regBad)
	_, reuseErrRaw, _ := cReuse.Read(ctx)
	var reuseErr protocol.ErrorMessage
	_ = json.Unmarshal(reuseErrRaw, &reuseErr)
	if reuseErr.Code != protocol.ErrCodeChallengeInvalid {
		t.Fatalf("expected challenge_invalid on replayed challenge, got %+v", reuseErr)
	}
	_ = cReuse.CloseNow()

	// 5. Second concurrent valid session for Peer A exceeds MaxSessionsPerPeer=1.
	cA2, _, _ := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc})
	_, chalRawA2, _ := cA2.Read(ctx)
	var chalA2 protocol.ChallengeMessage
	_ = json.Unmarshal(chalRawA2, &chalA2)
	proofA2, _ := kpA.SignRegistrationChallenge(chalA2.Challenge, origin)
	authA2, _ := identity.SignHubPassphraseProof(hubSecret, chalA2.Challenge, origin, kpA.PeerID)
	regA2, _ := json.Marshal(protocol.RegisterMessage{
		V: protocol.Version, Type: protocol.TypeRegister, PeerID: kpA.PeerID,
		PublicKey: identity.EncodePublicKey(kpA.PublicKey), HubOrigin: origin,
		Challenge: chalA2.Challenge, Proof: proofA2, HubAuth: authA2,
	})
	_ = cA2.Write(ctx, websocket.MessageText, regA2)
	_, limRaw, _ := cA2.Read(ctx)
	var limErr protocol.ErrorMessage
	_ = json.Unmarshal(limRaw, &limErr)
	if limErr.Code != protocol.ErrCodeSessionLimit {
		t.Fatalf("expected session_limit_exceeded, got %+v", limErr)
	}
	_ = cA2.CloseNow()

	// 6. Passphrase-scoped broadcast isolation:
	//    Peer B joins channel "room-alpha"; Peer C joins channel "room-beta".
	//    Peer A broadcasts on "room-alpha" -> ONLY Peer B receives Peer A!
	cB, _ := dialAndRegister(t, ctx, hc, wsURL, origin, hubSecret, kpB)
	defer cB.CloseNow()
	cC, _ := dialAndRegister(t, ctx, hc, wsURL, origin, hubSecret, kpC)
	defer cC.CloseNow()

	alphaKeys, _ := identity.DeriveChannelKeys("room-alpha")
	betaKeys, _ := identity.DeriveChannelKeys("room-beta")

	joinAlpha, _ := json.Marshal(protocol.ChannelJoinMessage{V: protocol.Version, Type: protocol.TypeChannelJoin, ChannelID: alphaKeys.ChannelID})
	joinBeta, _ := json.Marshal(protocol.ChannelJoinMessage{V: protocol.Version, Type: protocol.TypeChannelJoin, ChannelID: betaKeys.ChannelID})
	_ = cB.Write(ctx, websocket.MessageText, joinAlpha)
	_, _, _ = cB.Read(ctx) // initial empty snapshot for alpha
	_ = cC.Write(ctx, websocket.MessageText, joinBeta)
	_, _, _ = cC.Read(ctx) // initial empty snapshot for beta

	sealed, _ := identity.SealBroadcastMeta(alphaKeys.AuthKey, kpA.PeerID, alphaKeys.ChannelID, identity.BroadcastMeta{DisplayName: "peer-a"})
	_, bcastRaw, err := protocol.SignBroadcast(kpA, alphaKeys.ChannelID, true, sealed, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := cA.Write(ctx, websocket.MessageText, bcastRaw); err != nil {
		t.Fatal(err)
	}

	_, peersBRaw, err := cB.Read(ctx)
	if err != nil {
		t.Fatalf("read channel_peers on B: %v", err)
	}
	var snapB protocol.ChannelPeersMessage
	if err := json.Unmarshal(peersBRaw, &snapB); err != nil {
		t.Fatal(err)
	}
	if snapB.Type != protocol.TypeChannelPeers || snapB.ChannelID != alphaKeys.ChannelID || len(snapB.Peers) != 1 || snapB.Peers[0].PeerID != kpA.PeerID {
		t.Fatalf("unexpected alpha snapshot on B: %+v", snapB)
	}

	// Verify Peer C on room-beta receives NOTHING from room-alpha!
	cCtx, cCancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, leakRaw, leakErr := cC.Read(cCtx)
	cCancel()
	if leakErr == nil {
		t.Fatalf("blast radius leak: Peer C in beta received %s", string(leakRaw))
	}

	// Disconnect Peer A -> Peer B receives withdrawal snapshot with 0 peers.
	_ = cA.CloseNow()
	_, withdrawRaw, err := cB.Read(ctx)
	if err != nil {
		t.Fatalf("read withdrawal on B: %v", err)
	}
	var snapAfter protocol.ChannelPeersMessage
	_ = json.Unmarshal(withdrawRaw, &snapAfter)
	if len(snapAfter.Peers) != 0 {
		t.Fatalf("expected Peer A broadcast withdrawn on disconnect, got %+v", snapAfter.Peers)
	}
}

func TestHubZeroConfigAutoTLS(t *testing.T) {
	t.Parallel()

	srv, err := hub.New(&hub.Config{
		HTTPSListenAddr: "127.0.0.1:0",
		STUNSListenAddr: "127.0.0.1:0",
		AutoTLS:         true,
		EnableSTUN:      true,
		EnableTURN:      true,
	})
	if err != nil {
		t.Fatalf("zero-config AutoTLS hub.New: %v", err)
	}
	defer srv.Close()

	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true, //nolint:gosec // ephemeral self-signed test cert
			},
		},
	}
	resp, err := hc.Get("https://" + srv.HTTPSAddr().String() + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz on AutoTLS hub: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != `{"status":"ok"}` {
		t.Fatalf("unexpected /healthz response: %d %q", resp.StatusCode, string(body))
	}
}

func TestHubCustomCIDRAndPassphraseBroadcastAutoACL(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS := makeCert(t)
	kpA, _ := identity.GenerateKeyPair()
	kpB, _ := identity.GenerateKeyPair()
	kpC, _ := identity.GenerateKeyPair()

	customCIDR := netip.MustParsePrefix("10.99.0.0/24")
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "wss://" + ln.Addr().String()
	srv, err := hub.New(&hub.Config{
		HTTPSListener:   ln,
		TLSConfig:       srvTLS,
		HubOrigin:       origin,
		VirtualCIDR:     customCIDR,
		EnableSTUN:      true,
		STUNSListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if srv.VirtualCIDR() != customCIDR {
		t.Fatalf("srv.VirtualCIDR() = %s; want %s", srv.VirtualCIDR(), customCIDR)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cliTLS}}
	wsURL := origin + "/v1/signal"

	cA, regA := dialAndRegister(t, ctx, hc, wsURL, origin, "", kpA)
	defer cA.CloseNow()
	cB, regB := dialAndRegister(t, ctx, hc, wsURL, origin, "", kpB)
	defer cB.CloseNow()
	cC, _ := dialAndRegister(t, ctx, hc, wsURL, origin, "", kpC)
	defer cC.CloseNow()

	// Hub must assign every peer an IP inside its configured 10.99.0.0/24 CIDR.
	ipA, err := netip.ParseAddr(regA.AssignedIP)
	if err != nil || !customCIDR.Contains(ipA) || regA.VirtualCIDR != customCIDR.String() {
		t.Fatalf("unexpected hub CIDR/IP assignment for A: cidr=%q ip=%q", regA.VirtualCIDR, regA.AssignedIP)
	}
	ipB, err := netip.ParseAddr(regB.AssignedIP)
	if err != nil || !customCIDR.Contains(ipB) || regB.VirtualCIDR != customCIDR.String() {
		t.Fatalf("unexpected hub CIDR/IP assignment for B: cidr=%q ip=%q", regB.VirtualCIDR, regB.AssignedIP)
	}

	sendOffer := func(sender *websocket.Conn, from *identity.KeyPair, toPeerID string) string {
		t.Helper()
		sid, _ := protocol.NewSessionID()
		_, raw, sErr := protocol.SignEnvelope(
			from,
			protocol.TypeOffer,
			toPeerID,
			sid,
			0,
			0,
			time.Now().Add(60*time.Second).Unix(),
			protocol.SDPBody{SDP: "v=0\r\n"},
		)
		if sErr != nil {
			t.Fatal(sErr)
		}
		if wErr := sender.Write(ctx, websocket.MessageText, raw); wErr != nil {
			t.Fatal(wErr)
		}
		return sid
	}

	expectErrCode := func(conn *websocket.Conn, wantCode string) {
		t.Helper()
		_, raw, rErr := conn.Read(ctx)
		if rErr != nil {
			t.Fatalf("read error frame: %v", rErr)
		}
		var em protocol.ErrorMessage
		if uErr := json.Unmarshal(raw, &em); uErr != nil || em.Type != protocol.TypeError || em.Code != wantCode {
			t.Fatalf("expected error code %q, got %s", wantCode, string(raw))
		}
	}

	// 1. Target A is NOT broadcasting -> offer from B MUST be denied by server auto-ACL.
	sendOffer(cB, kpB, kpA.PeerID)
	expectErrCode(cB, protocol.ErrCodeNotAuthorized)

	// 2. Target A broadcasts on "room-alpha", C joins "room-beta", B joins "room-alpha".
	alphaKeys, _ := identity.DeriveChannelKeys("room-alpha")
	betaKeys, _ := identity.DeriveChannelKeys("room-beta")

	joinAlpha, _ := json.Marshal(protocol.ChannelJoinMessage{V: protocol.Version, Type: protocol.TypeChannelJoin, ChannelID: alphaKeys.ChannelID})
	joinBeta, _ := json.Marshal(protocol.ChannelJoinMessage{V: protocol.Version, Type: protocol.TypeChannelJoin, ChannelID: betaKeys.ChannelID})
	_ = cB.Write(ctx, websocket.MessageText, joinAlpha)
	_, _, _ = cB.Read(ctx) // empty snapshot
	_ = cC.Write(ctx, websocket.MessageText, joinBeta)
	_, _, _ = cC.Read(ctx) // empty snapshot

	_, bcastOn, _ := protocol.SignBroadcast(kpA, alphaKeys.ChannelID, true, "", time.Now().Unix())
	_ = cA.Write(ctx, websocket.MessageText, bcastOn)
	_, _, _ = cB.Read(ctx) // snapshot with A

	// 3. Peer C (different passphrase) -> A MUST be denied by server auto-ACL.
	sendOffer(cC, kpC, kpA.PeerID)
	expectErrCode(cC, protocol.ErrCodeNotAuthorized)

	// 4. Peer B (shared passphrase, A broadcasting) -> A MUST be allowed by server auto-ACL.
	allowedSID := sendOffer(cB, kpB, kpA.PeerID)
	_, fwdRaw, err := cA.Read(ctx)
	if err != nil {
		t.Fatalf("read forwarded offer on A: %v", err)
	}
	var fwdEnv protocol.SignalEnvelope
	if err := json.Unmarshal(fwdRaw, &fwdEnv); err != nil || fwdEnv.SessionID != allowedSID || fwdEnv.From != kpB.PeerID {
		t.Fatalf("unexpected forwarded offer on A: %s", string(fwdRaw))
	}

	// 5. Target A turns broadcast OFF -> existing session answer still forwards, NEW session denied!
	_, bcastOff, _ := protocol.SignBroadcast(kpA, alphaKeys.ChannelID, false, "", time.Now().Unix())
	_ = cA.Write(ctx, websocket.MessageText, bcastOff)
	_, _, _ = cB.Read(ctx) // empty snapshot confirming withdrawal

	_, ansRaw, _ := protocol.SignEnvelope(kpA, protocol.TypeAnswer, kpB.PeerID, allowedSID, 0, 0, time.Now().Add(60*time.Second).Unix(), protocol.SDPBody{SDP: "v=0\r\n"})
	_ = cA.Write(ctx, websocket.MessageText, ansRaw)
	_, gotAnsRaw, err := cB.Read(ctx)
	if err != nil {
		t.Fatalf("expected existing session answer to pass after broadcast off: %v", err)
	}
	var gotAns protocol.SignalEnvelope
	if err := json.Unmarshal(gotAnsRaw, &gotAns); err != nil || gotAns.Type != protocol.TypeAnswer || gotAns.SessionID != allowedSID {
		t.Fatalf("unexpected answer frame: %s", string(gotAnsRaw))
	}

	// Brand-new offer from B -> A after A turned broadcast OFF MUST be denied by server auto-ACL.
	sendOffer(cB, kpB, kpA.PeerID)
	expectErrCode(cB, protocol.ErrCodeNotAuthorized)

	if st := srv.Stats(); st.AutoACLDenied < 3 {
		t.Fatalf("expected AutoACLDenied >= 3, got %+v", st)
	}
}
