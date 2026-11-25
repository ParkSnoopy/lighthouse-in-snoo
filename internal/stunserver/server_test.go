package stunserver_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v5"

	"lighthouse-in-snoo/internal/stunserver"
)

func TestSTUNBindingIPv4AndIPv6AndRejectTURN(t *testing.T) {
	t.Parallel()

	t.Run("IPv4 binding and TURN allocate rejection", func(t *testing.T) {
		t.Parallel()
		srv, err := stunserver.New(stunserver.Config{
			ListenAddr: "127.0.0.1:0",
			PerIPRPS:   100,
			PerIPBurst: 200,
		})
		if err != nil {
			t.Fatalf("start stun server: %v", err)
		}
		defer srv.Close()

		clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer clientConn.Close()
		_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))

		req := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
		if _, err := clientConn.WriteTo(req.Raw, srv.LocalAddr()); err != nil {
			t.Fatal(err)
		}

		buf := make([]byte, 576)
		n, _, err := clientConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom binding response: %v", err)
		}
		var resp stun.Message
		if err := stun.Decode(buf[:n], &resp); err != nil {
			t.Fatalf("Decode response: %v", err)
		}
		if resp.Type != stun.BindingSuccess {
			t.Fatalf("got %v, want BindingSuccess", resp.Type)
		}
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(&resp); err != nil {
			t.Fatalf("GetFrom XORMappedAddress: %v", err)
		}
		localUDP := clientConn.LocalAddr().(*net.UDPAddr)
		if !xorAddr.IP.Equal(localUDP.IP) || xorAddr.Port != localUDP.Port {
			t.Fatalf("mapped addr = %s:%d; want %s:%d", xorAddr.IP, xorAddr.Port, localUDP.IP, localUDP.Port)
		}

		// Send unsupported TURN Allocate request -> MUST receive ErrorResponse and increment UnsupportedMethods.
		allocType := stun.NewType(stun.MethodAllocate, stun.ClassRequest)
		allocReq := stun.MustBuild(stun.TransactionID, allocType, stun.Fingerprint)
		if _, err := clientConn.WriteTo(allocReq.Raw, srv.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		n, _, err = clientConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom allocate error response: %v", err)
		}
		resp.Reset()
		if err := stun.Decode(buf[:n], &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Type.Class != stun.ClassErrorResponse {
			t.Fatalf("expected ClassErrorResponse for TURN Allocate, got %v", resp.Type)
		}

		// Send oversized and malformed datagrams -> silently dropped, counters incremented.
		_, _ = clientConn.WriteTo(bytes.Repeat([]byte{0x42}, 900), srv.LocalAddr())
		_, _ = clientConn.WriteTo([]byte("not-a-stun-packet"), srv.LocalAddr())
		time.Sleep(30 * time.Millisecond)

		st := srv.Stats()
		if st.BindingResponses != 1 || st.UnsupportedMethods != 1 || st.OversizedPackets != 1 || st.MalformedPackets != 1 {
			t.Fatalf("unexpected STUN stats: %+v", st)
		}
	})

	t.Run("IPv6 binding", func(t *testing.T) {
		t.Parallel()
		lnConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
		if err != nil {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		srv, err := stunserver.New(stunserver.Config{PacketConn: lnConn})
		if err != nil {
			_ = lnConn.Close()
			t.Fatal(err)
		}
		defer func() {
			_ = srv.Close()
			_ = lnConn.Close()
		}()

		c6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer c6.Close()
		_ = c6.SetDeadline(time.Now().Add(3 * time.Second))

		req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		if _, err := c6.WriteTo(req.Raw, srv.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 576)
		n, _, err := c6.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		var resp stun.Message
		if err := stun.Decode(buf[:n], &resp); err != nil {
			t.Fatal(err)
		}
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(&resp); err != nil {
			t.Fatal(err)
		}
		localUDP := c6.LocalAddr().(*net.UDPAddr)
		if !xorAddr.IP.Equal(localUDP.IP) || xorAddr.Port != localUDP.Port {
			t.Fatalf("ipv6 mapped = [%s]:%d; want [%s]:%d", xorAddr.IP, xorAddr.Port, localUDP.IP, localUDP.Port)
		}
	})
}
