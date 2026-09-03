//go:build !linux

package hostnet

import "fmt"

func DefaultExternalInterface() (string, error) {
	return "", fmt.Errorf("default interface detection requires Linux")
}
