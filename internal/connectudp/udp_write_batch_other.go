//go:build !linux

package connectudp

import "net"

type udpWriteBatch struct{ conn *net.UDPConn }

func newUDPWriteBatch(conn *net.UDPConn) *udpWriteBatch { return &udpWriteBatch{conn: conn} }

func (b *udpWriteBatch) Write(payloads [][]byte) (int, error) {
	written := 0
	for _, payload := range payloads {
		if _, err := b.conn.Write(payload); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}
