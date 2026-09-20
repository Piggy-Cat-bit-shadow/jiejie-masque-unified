package connectudp

import (
	"io"

	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
)

func skipCapsules(str quicvarint.Reader) error {
	p := http3.NewCapsuleParser(str)
	for {
		_, r, err := p.Next()
		if err != nil {
			return err
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			return err
		}
	}
}
