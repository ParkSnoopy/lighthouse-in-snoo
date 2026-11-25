package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
)

const (
	// DefaultMTU keeps raw IP packets comfortably under the 16 KiB WebRTC SCTP limit
	// and avoids outer UDP fragmentation on standard 1500-byte paths.
	DefaultMTU = 1380
	// DefaultSubnetPrefixBits is the default Lighthouse virtual IPv4 mask (10.88.0.0/16).
	DefaultSubnetPrefixBits = 16
)

var (
	ErrDeviceClosed  = errors.New("tun: device closed")
	ErrInvalidPacket = errors.New("tun: malformed IP packet")
)

// Device abstracts an OS virtual network interface (TUN) or an in-memory test device.
type Device interface {
	Name() string
	MTU() int
	ReadPacket(buf []byte) (int, error)
	WritePacket(pkt []byte) (int, error)
	Close() error
}

// ParsePacketEndpoints validates raw IPv4 or IPv6 packet framing and returns its source and destination IPs.
func ParsePacketEndpoints(pkt []byte) (src, dst netip.Addr, ok bool) {
	if len(pkt) < 20 {
		return netip.Addr{}, netip.Addr{}, false
	}
	ver := pkt[0] >> 4
	switch ver {
	case 4:
		ihl := int(pkt[0]&0x0F) * 4
		if ihl < 20 || len(pkt) < ihl {
			return netip.Addr{}, netip.Addr{}, false
		}
		totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
		if totalLen < ihl || totalLen > len(pkt) {
			return netip.Addr{}, netip.Addr{}, false
		}
		src = netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
		dst = netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
		return src, dst, true

	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, netip.Addr{}, false
		}
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if 40+payloadLen > len(pkt) {
			return netip.Addr{}, netip.Addr{}, false
		}
		var s, d [16]byte
		copy(s[:], pkt[8:24])
		copy(d[:], pkt[24:40])
		return netip.AddrFrom16(s), netip.AddrFrom16(d), true

	default:
		return netip.Addr{}, netip.Addr{}, false
	}
}

// MemoryDevice is a pure-Go in-memory TUN Device for unprivileged testing and embedded bindings.
type MemoryDevice struct {
	name      string
	mtu       int
	outbound  chan []byte // OS -> Router (ReadPacket)
	inbound   chan []byte // Router -> OS (WritePacket)
	closedCh  chan struct{}
	closeOnce sync.Once
}

// NewMemoryDevice constructs a buffered in-memory TUN Device.
func NewMemoryDevice(name string, mtu int) *MemoryDevice {
	if name == "" {
		name = "lh-mem0"
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	return &MemoryDevice{
		name:     name,
		mtu:      mtu,
		outbound: make(chan []byte, 256),
		inbound:  make(chan []byte, 256),
		closedCh: make(chan struct{}),
	}
}

// Name returns the virtual interface name.
func (m *MemoryDevice) Name() string { return m.name }

// MTU returns the configured interface MTU.
func (m *MemoryDevice) MTU() int { return m.mtu }

// ReadPacket reads the next outbound raw IP packet injected from the host side.
func (m *MemoryDevice) ReadPacket(buf []byte) (int, error) {
	select {
	case <-m.closedCh:
		return 0, io.EOF
	case pkt := <-m.outbound:
		if len(pkt) > len(buf) {
			return 0, io.ErrShortBuffer
		}
		return copy(buf, pkt), nil
	}
}

// WritePacket delivers an inbound raw IP packet from a verified peer session to the host side.
func (m *MemoryDevice) WritePacket(pkt []byte) (int, error) {
	cp := append([]byte(nil), pkt...)
	select {
	case <-m.closedCh:
		return 0, ErrDeviceClosed
	case m.inbound <- cp:
		return len(cp), nil
	}
}

// InjectOutbound simulates the OS kernel transmitting a raw IP packet into the TUN interface.
func (m *MemoryDevice) InjectOutbound(ctx context.Context, pkt []byte) error {
	cp := append([]byte(nil), pkt...)
	select {
	case <-m.closedCh:
		return ErrDeviceClosed
	case <-ctx.Done():
		return ctx.Err()
	case m.outbound <- cp:
		return nil
	}
}

// ReadInbound reads the next raw IP packet delivered to the OS kernel by the TUN router.
func (m *MemoryDevice) ReadInbound(ctx context.Context) ([]byte, error) {
	select {
	case <-m.closedCh:
		return nil, ErrDeviceClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	case pkt := <-m.inbound:
		return pkt, nil
	}
}

// Close closes the in-memory TUN device and unblocks all readers/writers.
func (m *MemoryDevice) Close() error {
	m.closeOnce.Do(func() {
		close(m.closedCh)
	})
	return nil
}
