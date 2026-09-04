package main

import (
	"context"

	"github.com/metacubex/quic-go"
)

type cubicCongestionConnection interface {
	SetCubicCongestionControl()
}

// configureCongestionControl is called once from HTTP/3 ConnContext, after
// accept and before HTTP/3 opens its control stream or accepts CONNECT-IP data.
func configureCongestionControl(controller string, conn cubicCongestionConnection) {
	if controller == "cubic" {
		conn.SetCubicCongestionControl()
	}
}

func connectIPConnContext(controller string) func(context.Context, *quic.Conn) context.Context {
	return func(ctx context.Context, conn *quic.Conn) context.Context {
		configureCongestionControl(controller, conn)
		return ctx
	}
}
