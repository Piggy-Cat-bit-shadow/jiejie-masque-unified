package notify

import (
	"net"
	"runtime"
	"testing"
	"time"
)

func TestSendWithoutSystemdIsNoop(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := Send("READY=1"); err != nil {
		t.Fatal(err)
	}
}

func TestSendFilesystemSocket(t *testing.T) {
	socket := t.TempDir() + "/notify.sock"
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", socket)
	if err := Send("READY=1"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	listener.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := listener.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Fatalf("unexpected payload %q", got)
	}
}

func TestSendAbstractSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("abstract unix sockets are Linux-specific")
	}
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "\x00jiejie-masque-notify-test", Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", "@jiejie-masque-notify-test")
	if err := Send("WATCHDOG=1"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	listener.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := listener.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "WATCHDOG=1" {
		t.Fatalf("unexpected payload %q", got)
	}
}
