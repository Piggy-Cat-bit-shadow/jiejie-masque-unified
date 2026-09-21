//go:build !linux

package hostnet

import "fmt"

func DefaultExternalInterface() (string, error) {
	return "", fmt.Errorf("default interface detection requires Linux")
}

func DefaultExternalInterface4() (string, error) { return DefaultExternalInterface() }
func DefaultExternalInterface6() (string, error) { return DefaultExternalInterface() }
