package notify

import "testing"

func TestSendWithoutSystemdIsNoop(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := Send("READY=1"); err != nil {
		t.Fatal(err)
	}
}
