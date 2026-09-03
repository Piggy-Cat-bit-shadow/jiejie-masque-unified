//go:build linux

package hostnet

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func DefaultExternalInterface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return "", fmt.Errorf("default route is unavailable")
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[1] == "00000000" && fields[3] != "0" {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("default route is unavailable")
}
