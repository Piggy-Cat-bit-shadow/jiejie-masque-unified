//go:build linux

package hostnet

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func DefaultExternalInterface() (string, error) {
	if iface, err := DefaultExternalInterface4(); err == nil {
		return iface, nil
	}
	return DefaultExternalInterface6()
}

func DefaultExternalInterface4() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()
	return parseIPv4DefaultRoute(f)
}

func DefaultExternalInterface6() (string, error) {
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
	bestIface := ""
	bestMetric := uint64(^uint64(0))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[0] != strings.Repeat("0", 32) || fields[1] != "00" || fields[9] == "" {
			continue
		}
		metric, metricErr := strconv.ParseUint(fields[5], 16, 64)
		flags, flagsErr := strconv.ParseUint(fields[8], 16, 64)
		if metricErr != nil || flagsErr != nil || flags&1 == 0 || flags&0x200 != 0 {
			continue
		}
		if bestIface == "" || metric < bestMetric {
			bestIface, bestMetric = fields[9], metric
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if bestIface == "" {
		return "", fmt.Errorf("usable IPv6 default route is unavailable")
	}
	return bestIface, nil
}
