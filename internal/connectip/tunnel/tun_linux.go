//go:build linux

package tunnel

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type Device struct {
	f          *os.File
	Name       string
	MTU        int
	offload    bool
	txGRO      bool
	txGROBuf   []byte
	txGROMu    sync.Mutex
	readBuffer [65545]byte
}

type tunFDOps struct {
	open        func(string, int, uint32) (int, error)
	ioctl       func(int, uint, *unix.Ifreq) error
	setNonblock func(int, bool) error
	setOffload  func(int, int) error
	newFile     func(uintptr, string) *os.File
	close       func(int) error
}

var systemTunFDOps = tunFDOps{
	open:        unix.Open,
	ioctl:       unix.IoctlIfreq,
	setNonblock: unix.SetNonblock,
	setOffload: func(fd, flags int) error {
		return unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, flags)
	},
	newFile: os.NewFile,
	close:   unix.Close,
}

func Open(name string, mtu int, offload bool, txGRO bool) (*Device, error) {
	return openTun(name, mtu, offload, txGRO, systemTunFDOps)
}

func openTun(name string, mtu int, offload, txGRO bool, ops tunFDOps) (*Device, error) {
	fd, err := ops.open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	closeFD := true
	defer func() {
		if closeFD {
			_ = ops.close(fd)
		}
	}()
	ifr, err := newIfreq(name, offload)
	if err != nil {
		return nil, err
	}
	if err = ops.ioctl(fd, unix.TUNSETIFF, ifr); err != nil {
		return nil, fmt.Errorf("TUNSETIFF: %w", err)
	}
	if err = ops.setNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("set TUN nonblocking: %w", err)
	}
	f := ops.newFile(uintptr(fd), "/dev/net/tun")
	if f == nil {
		return nil, fmt.Errorf("create TUN file")
	}
	closeFD = false
	if offload {
		if err = ops.setOffload(fd, unix.TUN_F_CSUM|unix.TUN_F_TSO4|unix.TUN_F_TSO6); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("TUNSETOFFLOAD: %w", err)
		}
	}
	return &Device{f: f, Name: ifr.Name(), MTU: mtu, offload: offload, txGRO: txGRO}, nil
}

func newIfreq(name string, offload bool) (*unix.Ifreq, error) {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if offload {
		flags |= unix.IFF_VNET_HDR
	}
	ifr.SetUint16(flags)
	return ifr, nil
}

func (d *Device) Configure(prefix netip.Prefix) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return configureInterface(d.Name, prefix, d.MTU, func(req uint, ifr *unix.Ifreq) error {
		return unix.IoctlIfreq(fd, req, ifr)
	})
}

func configureInterface(name string, prefix netip.Prefix, mtu int, ioctl func(uint, *unix.Ifreq) error) error {
	if !prefix.Addr().Is4() || prefix.Bits() < 0 || prefix.Bits() > 32 {
		return fmt.Errorf("invalid IPv4 prefix %q", prefix)
	}
	setAddr := func(req uint, addr []byte) error {
		ifr, err := unix.NewIfreq(name)
		if err != nil {
			return err
		}
		if err = ifr.SetInet4Addr(addr); err != nil {
			return err
		}
		return ioctl(req, ifr)
	}
	if err := setAddr(unix.SIOCSIFADDR, prefix.Addr().AsSlice()); err != nil {
		return fmt.Errorf("set IPv4 address: %w", err)
	}
	if err := setAddr(unix.SIOCSIFNETMASK, net.CIDRMask(prefix.Bits(), 32)); err != nil {
		return fmt.Errorf("set IPv4 netmask: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	ifr.SetUint32(uint32(mtu))
	if err = ioctl(unix.SIOCSIFMTU, ifr); err != nil {
		return fmt.Errorf("set MTU: %w", err)
	}
	ifr, err = unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err = ioctl(unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("get interface flags: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err = ioctl(unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("set interface UP: %w", err)
	}
	return nil
}

func (d *Device) Read(p []byte) (int, error) { return d.f.Read(p) }
func (d *Device) Write(p []byte) (int, error) {
	if !d.offload {
		return d.f.Write(p)
	}
	var header [10]byte
	raw, err := d.f.SyscallConn()
	if err != nil {
		return 0, err
	}
	n := 0
	err = raw.Write(func(fd uintptr) bool {
		n, err = unix.Writev(int(fd), [][]byte{header[:], p})
		return err != unix.EAGAIN && err != unix.EWOULDBLOCK
	})
	if err != nil {
		return 0, err
	}
	if n != len(header)+len(p) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}
func (d *Device) Close() error         { return d.f.Close() }
func (d *Device) OffloadEnabled() bool { return d.offload }
func (d *Device) TXGROEnabled() bool   { return d.txGRO }
