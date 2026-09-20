//go:build !linux

package main

import (
	"fmt"
	"net"
)

type socketBufferSizes struct{ Receive, Send int }

func readSocketBufferSizes(net.PacketConn) (socketBufferSizes, error) {
	return socketBufferSizes{}, fmt.Errorf("socket buffer inspection is Linux-only")
}
