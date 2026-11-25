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
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"

	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/protocol"
)

func makeCert(t *testing.T) (*tls.Config, *tls.Config) {
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

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}},
	}
	cliTLS := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	return srvTLS, cliTLS
}

func TestHubSingleUseChallengeSessionLimitAndRevocation(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS := makeCert(t)
	kpA, _ := identity.GenerateKeyPair()
	kpB, _ := identity.GenerateKeyPair()

	pol := identity.PolicyConfig{
		Version: 1,
		TrustedPeers: []identity.TrustedPeerEntry{
			{PeerID: kpA.PeerID, PublicKey: identity.EncodePublicKey(kpA.PublicKey)},
			{PeerID: kpB.PeerID, PublicKey: identity.EncodePublicKey(kpB.PublicKey)},
		},
		ACLRules: []identity.ACLRule{{PeerA: kpA.PeerID, PeerB: kpB.PeerID}},
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "wss://" + ln.Addr().String()
	srv, err := hub.New(hub.Config{
		HTTPSListener:      ln,
		TLSConfig:          srvTLS,
		HubOrigin:          origin,
		Policy:             pol,
		MaxSessionsPerPeer: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cliTLS}}
	wsURL := origin + "/v1/signal"

	// 1. Sending lookup BEFORE register MUST fail with unauthenticated.
	cUnauth, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = cUnauth.Read(ctx) // challenge
	_ = cUnauth.Write(ctx, websocket.MessageText, []byte(`{"v":1,"type":"lookup","target":"`+kpB.PeerID+`"}`))
	_, rawErr, _ := cUnauth.Read(ctx)
	var em protocol.ErrorMessage
	_ = json.Unmarshal(rawErr, &em)
	if em.Code != protocol.ErrCodeUnauthenticated {
		t.Fatalf("expected unauthenticated error, got %+v", em)
	}
	_ = cUnauth.CloseNow()

	// 2. Register session #1 for Peer A, then verify 2nd concurrent session exceeds MaxSessionsPerPeer=1!
	c1, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		t.Fatal(err)
	}
	defer c1.CloseNow()
	_, chalRaw1, _ := c1.Read(ctx)
	var chal1 protocol.ChallengeMessage
	_ = json.Unmarshal(chalRaw1, &chal1)
	proof1, _ := kpA.SignRegistrationChallenge(chal1.Challenge, origin)
	reg1, _ := json.Marshal(protocol.RegisterMessage{
		V: 1, Type: protocol.TypeRegister, PeerID: kpA.PeerID,
		PublicKey: identity.EncodePublicKey(kpA.PublicKey), HubOrigin: origin,
		Challenge: chal1.Challenge, Proof: proof1,
	})
	_ = c1.Write(ctx, websocket.MessageText, reg1)
	_, _, _ = c1.Read(ctx) // registered

	// Attempt to reuse challenge #1 on a second connection -> MUST fail (single-use per session)!
	cReuse, _, _ := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc})
	_, _, _ = cReuse.Read(ctx)
	_ = cReuse.Write(ctx, websocket.MessageText, reg1)
	_, reuseErrRaw, _ := cReuse.Read(ctx)
	var reuseErr protocol.ErrorMessage
	_ = json.Unmarshal(reuseErrRaw, &reuseErr)
	if reuseErr.Code != protocol.ErrCodeChallengeInvalid {
		t.Fatalf("expected challenge_invalid on replayed challenge, got %+v", reuseErr)
	}
	_ = cReuse.CloseNow()

	// Attempt 2nd valid registration while session #1 is active -> MUST hit session_limit_exceeded!
	c2, _, _ := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: hc})
	_, chalRaw2, _ := c2.Read(ctx)
	var chal2 protocol.ChallengeMessage
	_ = json.Unmarshal(chalRaw2, &chal2)
	proof2, _ := kpA.SignRegistrationChallenge(chal2.Challenge, origin)
	reg2, _ := json.Marshal(protocol.RegisterMessage{
		V: 1, Type: protocol.TypeRegister, PeerID: kpA.PeerID,
		PublicKey: identity.EncodePublicKey(kpA.PublicKey), HubOrigin: origin,
		Challenge: chal2.Challenge, Proof: proof2,
	})
	_ = c2.Write(ctx, websocket.MessageText, reg2)
	_, limRaw, _ := c2.Read(ctx)
	var limErr protocol.ErrorMessage
	_ = json.Unmarshal(limRaw, &limErr)
	if limErr.Code != protocol.ErrCodeSessionLimit {
		t.Fatalf("expected session_limit_exceeded, got %+v", limErr)
	}
	_ = c2.CloseNow()

	// 3. Reload policy revoking Peer A -> active session #1 is immediately evicted!
	pol.RevokedPeers = []string{kpA.PeerID}
	if err := srv.ReloadPolicy(pol); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c1.Read(ctx); err == nil {
		t.Fatal("expected revoked peer WSS session to be closed")
	}
}
