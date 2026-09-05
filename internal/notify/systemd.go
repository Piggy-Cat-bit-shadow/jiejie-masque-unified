package notify

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Send sends one systemd notification. With no NOTIFY_SOCKET it is a no-op,
// which keeps local and non-systemd execution unchanged.
func Send(state string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// Enabled reports whether a notification socket is configured.
func Enabled() bool { return os.Getenv("NOTIFY_SOCKET") != "" }

// WatchdogInterval returns a heartbeat interval no greater than half of the
// systemd watchdog deadline. It is disabled unless both systemd notification
// and watchdog environments are valid for this process.
func WatchdogInterval() (time.Duration, bool) {
	if !Enabled() {
		return 0, false
	}
	if pidText := os.Getenv("WATCHDOG_PID"); pidText != "" {
		pid, err := strconv.Atoi(pidText)
		if err != nil || pid != os.Getpid() {
			return 0, false
		}
	}
	usec, err := strconv.ParseUint(os.Getenv("WATCHDOG_USEC"), 10, 63)
	if err != nil || usec == 0 || usec > uint64(time.Duration(1<<63-1)/time.Microsecond) {
		return 0, false
	}
	interval := time.Duration(usec) * time.Microsecond / 2
	if interval <= 0 {
		return 0, false
	}
	return interval, true
}
