//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

type socketBufferSizes struct{ Receive, Send int }

func readSocketBufferSizes(pc net.PacketConn) (socketBufferSizes, error) {
	sc, ok := pc.(syscallConnProvider)
	if !ok {
		return socketBufferSizes{}, fmt.Errorf("packet connection does not expose a file descriptor")
	}
	var out socketBufferSizes
	var runErr error
	raw, err := sc.SyscallConn()
	if err != nil {
		return out, err
	}
	err = raw.Control(func(fd uintptr) {
		out.Receive, runErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if runErr == nil {
			out.Send, runErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
		}
	})
	if err != nil {
		return out, err
	}
	return out, runErr
}

type syscallConnProvider interface {
	SyscallConn() (syscall.RawConn, error)
}
