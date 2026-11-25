//go:build linux

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LinuxConfig configures binding a real Linux /dev/net/tun Layer-3 TUN interface.
type LinuxConfig struct {
	Name        string       // Requested interface name (default "lh0", max 15 ASCII bytes).
	LocalCIDR   netip.Prefix // Local virtual IP/mask to assign (e.g. 10.88.x.y/16).
	MTU         int          // Interface MTU (default 1380).
	ConfigureOS bool         // Assign IP, MTU, and bring link UP via `ip`.
}

type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

// LinuxDevice wraps a live Linux /dev/net/tun character device.
type LinuxDevice struct {
	name      string
	mtu       int
	file      *os.File
	closeOnce sync.Once
}

// OpenLinux creates and binds a Linux TUN interface (IFF_TUN | IFF_NO_PI).
func OpenLinux(cfg LinuxConfig) (*LinuxDevice, error) {
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		name = "lh0"
	}
	if len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("tun: interface name %q exceeds %d bytes", name, unix.IFNAMSIZ-1)
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var req ifreqFlags
	copy(req.Name[:], name)
	req.Flags = unix.IFF_TUN | unix.IFF_NO_PI

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF (%s): %w", name, errno)
	}

	actualName := string(bytes.TrimRight(req.Name[:], "\x00"))
	file := os.NewFile(uintptr(fd), "/dev/net/tun")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("tun: failed to wrap TUN file descriptor")
	}

	if cfg.ConfigureOS && cfg.LocalCIDR.IsValid() {
		if err := configureLinuxInterface(actualName, cfg.LocalCIDR, mtu); err != nil {
			_ = file.Close()
			return nil, err
		}
	}

	return &LinuxDevice{
		name: actualName,
		mtu:  mtu,
		file: file,
	}, nil
}

func configureLinuxInterface(ifName string, cidr netip.Prefix, mtu int) error {
	cmds := [][]string{
		{"addr", "replace", cidr.String(), "dev", ifName},
		{"link", "set", "dev", ifName, "mtu", strconv.Itoa(mtu), "up"},
	}
	for _, args := range cmds {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Name returns the kernel-assigned interface name.
func (d *LinuxDevice) Name() string { return d.name }

// MTU returns the configured interface MTU.
func (d *LinuxDevice) MTU() int { return d.mtu }

// ReadPacket reads one raw IP packet from the Linux TUN interface.
func (d *LinuxDevice) ReadPacket(buf []byte) (int, error) {
	return d.file.Read(buf)
}

// WritePacket injects one raw IP packet into the Linux TUN interface.
func (d *LinuxDevice) WritePacket(pkt []byte) (int, error) {
	return d.file.Write(pkt)
}

// Close closes the TUN file descriptor and releases the virtual network interface.
func (d *LinuxDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		err = d.file.Close()
	})
	return err
}
