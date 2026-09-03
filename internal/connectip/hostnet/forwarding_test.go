package hostnet

import "testing"

func TestCheckIPv4Forwarding(t *testing.T) {
	original := readForwarding
	t.Cleanup(func() { readForwarding = original })
	readForwarding = func() ([]byte, error) { return []byte("1\n"), nil }
	if err := CheckIPv4Forwarding(); err != nil {
		t.Fatal(err)
	}
	readForwarding = func() ([]byte, error) { return []byte("0\n"), nil }
	if err := CheckIPv4Forwarding(); err == nil {
		t.Fatal("expected disabled forwarding to fail")
	}
}
