package connectudp

import (
	"io"
	"log"

	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
)

func skipCapsules(str quicvarint.Reader) error {
	p := http3.NewCapsuleParser(str)
	for {
		ct, r, err := p.Next()
		if err != nil {
			return err
		}
		log.Printf("skipping capsule of type %d", ct)
		if _, err := io.Copy(io.Discard, r); err != nil {
			return err
		}
	}
}
