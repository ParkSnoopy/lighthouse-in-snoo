package tun

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/peer"
)

// RouteInfo describes one active user-authorized peer route bound to the TUN interface.
type RouteInfo struct {
	PeerID    string
	VirtualIP netip.Addr
}

// RouterStats reports non-sensitive TUN forwarding counters.
type RouterStats struct {
	PacketsTX       uint64
	PacketsRX       uint64
	BytesTX         uint64
	BytesRX         uint64
	DroppedUnrouted uint64
	DroppedSpoofed  uint64
	ActiveRoutes    int
}

// Router binds an OS TUN Device directly to user-authorized DTLS 1.3 peer sessions,
// enforcing cryptographic source-IP anti-spoofing in both directions.
type Router struct {
	dev     Device
	localIP netip.Addr

	mu        sync.RWMutex
	byIP      map[netip.Addr]*peer.Session
	byPeerID  map[string]netip.Addr
	stopCh    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	pktsTX  atomic.Uint64
	pktsRX  atomic.Uint64
	bytesTX atomic.Uint64
	bytesRX atomic.Uint64
	unroute atomic.Uint64
	spoofed atomic.Uint64
}

// NewRouter binds dev to localIP and begins forwarding outbound TUN packets to attached sessions.
func NewRouter(dev Device, localIP netip.Addr) (*Router, error) {
	if dev == nil {
		return nil, errors.New("tun: Device is required")
	}
	if !localIP.IsValid() {
		return nil, errors.New("tun: valid local virtual IP is required")
	}
	r := &Router{
		dev:      dev,
		localIP:  localIP,
		byIP:     make(map[netip.Addr]*peer.Session),
		byPeerID: make(map[string]netip.Addr),
		stopCh:   make(chan struct{}),
	}
	r.wg.Add(1)
	go r.outboundLoop()
	return r, nil
}

// LocalIP returns the local peer's virtual TUN IP address.
func (r *Router) LocalIP() netip.Addr {
	return r.localIP
}

// Device returns the underlying TUN Device.
func (r *Router) Device() Device {
	return r.dev
}

// AttachSession installs a TUN route for an authorized peer session and starts its inbound pump.
func (r *Router) AttachSession(sess *peer.Session) (netip.Addr, error) {
	if sess == nil {
		return netip.Addr{}, errors.New("tun: session is nil")
	}
	remoteID := sess.RemotePeerID()
	remoteIP, err := identity.VirtualIPv4FromPeerID(remoteID)
	if err != nil {
		return netip.Addr{}, err
	}

	r.mu.Lock()
	if cur := r.byIP[remoteIP]; cur == sess {
		r.mu.Unlock()
		return remoteIP, nil
	}
	if prevIP, ok := r.byPeerID[remoteID]; ok {
		delete(r.byIP, prevIP)
	}
	r.byIP[remoteIP] = sess
	r.byPeerID[remoteID] = remoteIP
	r.mu.Unlock()

	r.wg.Add(1)
	go r.inboundLoop(sess, remoteID, remoteIP)
	return remoteIP, nil
}

// DetachPeer removes the TUN route for peerID.
func (r *Router) DetachPeer(peerID string) {
	r.mu.Lock()
	if ip, ok := r.byPeerID[peerID]; ok {
		delete(r.byPeerID, peerID)
		delete(r.byIP, ip)
	}
	r.mu.Unlock()
}

// Routes returns a deterministic sorted snapshot of all active peer routes.
func (r *Router) Routes() []RouteInfo {
	r.mu.RLock()
	out := make([]RouteInfo, 0, len(r.byPeerID))
	for pid, ip := range r.byPeerID {
		out = append(out, RouteInfo{PeerID: pid, VirtualIP: ip})
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].PeerID < out[j].PeerID
	})
	return out
}

// Stats returns a snapshot of TUN routing counters.
func (r *Router) Stats() RouterStats {
	r.mu.RLock()
	routeCount := len(r.byIP)
	r.mu.RUnlock()
	return RouterStats{
		PacketsTX:       r.pktsTX.Load(),
		PacketsRX:       r.pktsRX.Load(),
		BytesTX:         r.bytesTX.Load(),
		BytesRX:         r.bytesRX.Load(),
		DroppedUnrouted: r.unroute.Load(),
		DroppedSpoofed:  r.spoofed.Load(),
		ActiveRoutes:    routeCount,
	}
}

// Close shuts down the router, stops all pumps, and closes the bound TUN device.
func (r *Router) Close() error {
	var closeErr error
	r.closeOnce.Do(func() {
		close(r.stopCh)
		closeErr = r.dev.Close()
		r.wg.Wait()
	})
	return closeErr
}

func (r *Router) outboundLoop() {
	defer r.wg.Done()
	mtu := r.dev.MTU()
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	buf := make([]byte, max(mtu+64, 2048))

	for {
		n, err := r.dev.ReadPacket(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		src, dst, ok := ParsePacketEndpoints(pkt)
		if !ok {
			r.spoofed.Add(1)
			continue
		}
		if src != r.localIP {
			r.spoofed.Add(1)
			continue
		}

		r.mu.RLock()
		sess := r.byIP[dst]
		r.mu.RUnlock()
		if sess == nil {
			r.unroute.Add(1)
			continue
		}

		cp := append([]byte(nil), pkt...)
		sendCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var sendErr error
		if sess.HasPacketChannel() {
			sendErr = sess.SendPacket(sendCtx, cp)
		} else {
			sendErr = sess.Send(sendCtx, cp)
		}
		if sendErr != nil && sess.HasPacketChannel() {
			sendErr = sess.Send(sendCtx, cp)
		}
		cancel()
		if sendErr == nil {
			r.pktsTX.Add(1)
			r.bytesTX.Add(uint64(len(cp)))
		}
	}
}

func (r *Router) inboundLoop(sess *peer.Session, remoteID string, remoteIP netip.Addr) {
	defer r.wg.Done()
	defer func() {
		r.mu.Lock()
		if cur := r.byIP[remoteIP]; cur == sess {
			delete(r.byIP, remoteIP)
			delete(r.byPeerID, remoteID)
		}
		r.mu.Unlock()
	}()

	handleInbound := func(pkt []byte) {
		src, dst, ok := ParsePacketEndpoints(pkt)
		if !ok || src != remoteIP || dst != r.localIP {
			r.spoofed.Add(1)
			return
		}
		if _, err := r.dev.WritePacket(pkt); err == nil {
			r.pktsRX.Add(1)
			r.bytesRX.Add(uint64(len(pkt)))
		}
	}

	for {
		select {
		case <-r.stopCh:
			return
		case <-sess.Closed():
			return
		case pkt, ok := <-sess.Packets():
			if !ok {
				return
			}
			handleInbound(pkt)
		case pkt, ok := <-sess.Messages():
			if !ok {
				return
			}
			handleInbound(pkt)
		}
	}
}
