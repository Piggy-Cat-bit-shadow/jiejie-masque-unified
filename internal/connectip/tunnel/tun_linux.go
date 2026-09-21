//go:build linux

package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type Device struct {
	f         *os.File
	Name      string
	MTU       int
	rxPackets atomic.Uint64
	rxBytes   atomic.Uint64
	txPackets atomic.Uint64
	txBytes   atomic.Uint64
}

type tunFDOps struct {
	open        func(string, int, uint32) (int, error)
	ioctl       func(int, uint, *unix.Ifreq) error
	setNonblock func(int, bool) error
	newFile     func(uintptr, string) *os.File
	close       func(int) error
}

var systemTunFDOps = tunFDOps{
	open:        unix.Open,
	ioctl:       unix.IoctlIfreq,
	setNonblock: unix.SetNonblock,
	newFile:     os.NewFile,
	close:       unix.Close,
}

func Open(name string, mtu int) (*Device, error) {
	return openTun(name, mtu, systemTunFDOps)
}

func openTun(name string, mtu int, ops tunFDOps) (*Device, error) {
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
	ifr, err := newIfreq(name)
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
	return &Device{f: f, Name: ifr.Name(), MTU: mtu}, nil
}

func newIfreq(name string) (*unix.Ifreq, error) {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	ifr.SetUint16(flags)
	return ifr, nil
}

func (d *Device) Configure(prefix netip.Prefix) error {
	return d.ConfigureAddresses([]netip.Prefix{prefix})
}

var configureIPv6Address = func(name string, prefix netip.Prefix) error {
	return configureIPv6AddressWithRunner(name, prefix, func(ctx context.Context, command string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, command, args...).CombinedOutput()
	})
}

func configureIPv6AddressWithRunner(name string, prefix netip.Prefix, run func(context.Context, string, ...string) ([]byte, error)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if out, err := run(ctx, "ip", "-6", "addr", "replace", prefix.String(), "dev", name, "nodad"); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("ip -6 addr replace timed out: %s", string(out))
		}
		return fmt.Errorf("ip -6 addr replace: %w: %s", err, string(out))
	}
	return nil
}

func (d *Device) ConfigureAddresses(prefixes []netip.Prefix) error {
	if len(prefixes) == 0 {
		return fmt.Errorf("at least one tunnel prefix is required")
	}
	var v4, v6 *netip.Prefix
	for i := range prefixes {
		p := prefixes[i]
		if p.Addr().Is4() {
			if v4 != nil {
				return fmt.Errorf("multiple IPv4 tunnel prefixes are unsupported")
			}
			v4 = &prefixes[i]
		}
		if p.Addr().Is6() {
			if v6 != nil {
				return fmt.Errorf("multiple IPv6 tunnel prefixes are unsupported")
			}
			v6 = &prefixes[i]
		}
	}
	if v4 == nil && v6 == nil {
		return fmt.Errorf("invalid tunnel prefixes")
	}
	if v4 != nil {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if err != nil {
			return err
		}
		err = configureInterface(d.Name, *v4, d.MTU, func(req uint, ifr *unix.Ifreq) error { return unix.IoctlIfreq(fd, req, ifr) })
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
	} else {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if err != nil {
			return err
		}
		ifr, err := unix.NewIfreq(d.Name)
		if err == nil {
			ifr.SetUint32(uint32(d.MTU))
			err = unix.IoctlIfreq(fd, unix.SIOCSIFMTU, ifr)
		}
		if err == nil {
			ifr, err = unix.NewIfreq(d.Name)
		}
		if err == nil {
			err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr)
		}
		if err == nil {
			ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
			err = unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
		}
		_ = unix.Close(fd)
		if err != nil {
			return fmt.Errorf("configure IPv6 TUN interface: %w", err)
		}
	}
	if v6 != nil {
		if err := configureIPv6Address(d.Name, *v6); err != nil {
			return err
		}
	}
	return nil
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

func (d *Device) Read(p []byte) (int, error) {
	n, err := d.f.Read(p)
	if err == nil {
		d.rxPackets.Add(1)
		d.rxBytes.Add(uint64(n))
	}
	return n, err
}
func (d *Device) Write(p []byte) (int, error) {
	n, err := d.f.Write(p)
	if err == nil {
		d.txPackets.Add(1)
		d.txBytes.Add(uint64(n))
	}
	return n, err
}

type Stats struct {
	RXPackets, RXBytes uint64
	TXPackets, TXBytes uint64
}

func (d *Device) Stats() Stats {
	return Stats{RXPackets: d.rxPackets.Load(), RXBytes: d.rxBytes.Load(), TXPackets: d.txPackets.Load(), TXBytes: d.txBytes.Load()}
}
func (d *Device) Close() error { return d.f.Close() }
