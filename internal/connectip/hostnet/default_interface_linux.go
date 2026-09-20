//go:build linux

package hostnet

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

func DefaultExternalInterface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if iface, err := parseIPv4DefaultRoute(f); err == nil {
		return iface, nil
	}
	return defaultIPv6Interface()
}

func parseIPv4DefaultRoute(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return "", fmt.Errorf("default route is unavailable")
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[1] == "00000000" && fields[3] != "0" {
			return fields[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("default route is unavailable")
}

func defaultIPv6Interface() (string, error) {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return "", err
	}
	defer f.Close()
	return parseIPv6DefaultRoute(f)
}

func parseIPv6DefaultRoute(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 10 && fields[0] == strings.Repeat("0", 32) && fields[1] == "00" && fields[9] != "" {
			return fields[9], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("default route is unavailable")
}
