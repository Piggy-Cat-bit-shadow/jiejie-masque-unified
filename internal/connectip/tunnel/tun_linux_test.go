//go:build linux

package tunnel

import (
	"errors"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenTunFDSetupOrder(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	fd, peer := fds[0], fds[1]
	defer unix.Close(peer)
	var events []string
	ops := tunFDOps{
		open: func(path string, flags int, mode uint32) (int, error) {
			events = append(events, "open")
			if path != "/dev/net/tun" || flags != unix.O_RDWR|unix.O_CLOEXEC {
				t.Fatalf("open(%q, %#x)", path, flags)
			}
			return fd, nil
		},
		ioctl: func(gotFD int, req uint, ifr *unix.Ifreq) error {
			events = append(events, "ioctl")
			if gotFD != fd || req != unix.TUNSETIFF {
				t.Fatalf("ioctl(%d, %#x)", gotFD, req)
			}
			return nil
		},
		setNonblock: func(gotFD int, nonblocking bool) error {
			events = append(events, "nonblock")
			if gotFD != fd || !nonblocking {
				t.Fatal("SetNonblock called with unexpected arguments")
			}
			return unix.SetNonblock(gotFD, nonblocking)
		},
		setOffload: func(int, int) error { t.Fatal("setOffload called in plain mode"); return nil },
		newFile: func(gotFD uintptr, name string) *os.File {
			events = append(events, "newfile")
			return os.NewFile(gotFD, name)
		},
		close: func(gotFD int) error { events = append(events, "close"); return unix.Close(gotFD) },
	}
	d, err := openTun("masque0", 1280, false, false, ops)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []string{"open", "ioctl", "nonblock", "newfile"}) {
		t.Fatalf("events = %v", events)
	}
	if d.Name != "masque0" || d.MTU != 1280 {
		t.Fatalf("device = %+v", d)
	}
	if _, err := unix.Write(peer, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Read(make([]byte, 1)); err != nil {
		t.Fatalf("Read API: %v", err)
	}
	if _, err := d.Write([]byte{1}); err != nil {
		t.Fatalf("Write API: %v", err)
	}
	if _, err := unix.Read(peer, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() { _, err := d.Read(make([]byte, 1)); readDone <- err }()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("blocked Read returned no error after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Read")
	}
}

func TestOpenTunClosesFDOnSetupErrors(t *testing.T) {
	tests := []struct {
		name, deviceName      string
		ioctlErr, nonblockErr error
		newFileNil            bool
	}{
		{name: "ifreq", deviceName: "interface-name-too-long"},
		{name: "ioctl", deviceName: "masque0", ioctlErr: errors.New("ioctl")},
		{name: "nonblock", deviceName: "masque0", nonblockErr: errors.New("nonblock")},
		{name: "newfile", deviceName: "masque0", newFileNil: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			closed := 0
			ops := tunFDOps{
				open:        func(string, int, uint32) (int, error) { return 123, nil },
				ioctl:       func(int, uint, *unix.Ifreq) error { return tt.ioctlErr },
				setNonblock: func(int, bool) error { return tt.nonblockErr },
				setOffload:  func(int, int) error { return nil },
				newFile: func(uintptr, string) *os.File {
					if tt.newFileNil {
						return nil
					}
					return os.NewFile(123, "/dev/net/tun")
				},
				close: func(int) error { closed++; return nil },
			}
			if _, err := openTun(tt.deviceName, 1280, false, false, ops); err == nil {
				t.Fatal("expected error")
			}
			if closed != 1 {
				t.Fatalf("close calls = %d", closed)
			}
		})
	}
}

func TestNewIfreq(t *testing.T) {
	ifr, err := newIfreq("masque0", false)
	if err != nil {
		t.Fatal(err)
	}
	if ifr.Name() != "masque0" {
		t.Fatalf("name = %q", ifr.Name())
	}
	if ifr.Uint16() != unix.IFF_TUN|unix.IFF_NO_PI {
		t.Fatalf("flags = %#x", ifr.Uint16())
	}
}

func TestNewIfreqOffload(t *testing.T) {
	ifr, err := newIfreq("masque0", true)
	if err != nil {
		t.Fatal(err)
	}
	if ifr.Uint16() != unix.IFF_TUN|unix.IFF_NO_PI|unix.IFF_VNET_HDR {
		t.Fatalf("flags = %#x", ifr.Uint16())
	}
}

func TestOpenTunOffloadFailureIsFatal(t *testing.T) {
	fd, err := unix.Dup(0)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	ops := tunFDOps{
		open:        func(string, int, uint32) (int, error) { return fd, nil },
		ioctl:       func(int, uint, *unix.Ifreq) error { return nil },
		setNonblock: func(int, bool) error { return nil },
		setOffload:  func(int, int) error { return errors.New("unsupported") },
		newFile:     func(gotFD uintptr, name string) *os.File { return os.NewFile(gotFD, name) },
		close:       func(int) error { closed = true; return nil },
	}
	if _, err := openTun("masque0", 1280, true, false, ops); err == nil {
		t.Fatal("expected TUNSETOFFLOAD failure")
	}
	if closed {
		t.Fatal("fd was closed through ops after ownership transferred to os.File")
	}
}

func TestOpenTunOffloadConfiguresTCPFlags(t *testing.T) {
	fd, err := unix.Dup(0)
	if err != nil {
		t.Fatal(err)
	}
	configured := 0
	ops := tunFDOps{
		open:        func(string, int, uint32) (int, error) { return fd, nil },
		ioctl:       func(int, uint, *unix.Ifreq) error { return nil },
		setNonblock: func(int, bool) error { return nil },
		setOffload: func(gotFD, flags int) error {
			if gotFD != fd {
				t.Fatalf("offload fd = %d", gotFD)
			}
			configured = flags
			return nil
		},
		newFile: func(gotFD uintptr, name string) *os.File { return os.NewFile(gotFD, name) },
		close:   unix.Close,
	}
	d, err := openTun("masque0", 1280, true, false, ops)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if !d.OffloadEnabled() {
		t.Fatal("offload device not marked enabled")
	}
	want := unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
	if configured != want {
		t.Fatalf("TUNSETOFFLOAD flags = %#x, want %#x", configured, want)
	}
}

func TestDeviceWriteOffloadPrependsGSONoneHeader(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	fd, peer := fds[0], fds[1]
	defer unix.Close(peer)
	d := &Device{f: os.NewFile(uintptr(fd), "test-tun"), offload: true}
	defer d.Close()
	payload := []byte{0x45, 0, 0, 20}
	if n, err := d.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	written := make([]byte, virtioNetHdrLen+len(payload))
	if n, err := unix.Read(peer, written); err != nil || n != len(written) {
		t.Fatalf("peer read = %d, %v", n, err)
	}
	for i, b := range written[:virtioNetHdrLen] {
		if b != 0 {
			t.Fatalf("virtio header[%d] = %d, want GSO_NONE zero header", i, b)
		}
	}
	if !reflect.DeepEqual(written[virtioNetHdrLen:], payload) {
		t.Fatalf("payload = %x", written[virtioNetHdrLen:])
	}
}

func TestConfigureInterfaceIsRepeatable(t *testing.T) {
	prefix := netip.MustParsePrefix("10.200.0.1/30")
	for i := 0; i < 2; i++ {
		var calls []struct {
			req uint
			ifr unix.Ifreq
		}
		err := configureInterface("masque0", prefix, 1280, func(req uint, ifr *unix.Ifreq) error {
			if req == unix.SIOCGIFFLAGS {
				ifr.SetUint16(unix.IFF_MULTICAST)
			}
			calls = append(calls, struct {
				req uint
				ifr unix.Ifreq
			}{req, *ifr})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(calls) != 5 {
			t.Fatalf("ioctl calls = %d, want 5", len(calls))
		}
		if calls[0].req != unix.SIOCSIFADDR || calls[1].req != unix.SIOCSIFNETMASK || calls[2].req != unix.SIOCSIFMTU || calls[3].req != unix.SIOCGIFFLAGS || calls[4].req != unix.SIOCSIFFLAGS {
			t.Fatal("unexpected ioctl sequence")
		}
		address, _ := calls[0].ifr.Inet4Addr()
		if got := netip.AddrFrom4([4]byte(address)); got != prefix.Addr() {
			t.Fatalf("address = %s", got)
		}
		if calls[2].ifr.Uint32() != 1280 {
			t.Fatalf("MTU = %d", calls[2].ifr.Uint32())
		}
		if calls[4].ifr.Uint16()&unix.IFF_UP == 0 {
			t.Fatal("interface is not UP")
		}
	}
}
