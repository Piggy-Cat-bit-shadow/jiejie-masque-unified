package main

import (
	"context"
	"fmt"

	"github.com/metacubex/quic-go"
)

type congestionControlConnection interface {
	SetCubicCongestionControl()
	SetBBRCongestionControl()
}

// configureCongestionControl is called once from HTTP/3 ConnContext, after
// accept and before HTTP/3 opens its control stream or accepts CONNECT-IP data.
func configureCongestionControl(controller string, conn congestionControlConnection) error {
	switch controller {
	case "", "default":
		return nil
	case "cubic":
		conn.SetCubicCongestionControl()
	case "bbr":
		conn.SetBBRCongestionControl()
	default:
		return fmt.Errorf("unsupported QUIC congestion controller %q (want default, cubic, or bbr)", controller)
	}
	return nil
}

func connectIPConnContext(controller string) func(context.Context, *quic.Conn) context.Context {
	return func(ctx context.Context, conn *quic.Conn) context.Context {
		if err := configureCongestionControl(controller, conn); err != nil {
			_ = conn.CloseWithError(0, err.Error())
		}
		return ctx
	}
}
