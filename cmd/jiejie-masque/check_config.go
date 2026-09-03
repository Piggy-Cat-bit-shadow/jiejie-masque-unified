package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/quicstate"
	"github.com/metacubex/tls"
)

func checkConfig(path string) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	if err := quicstate.ValidateExisting(c.QUIC.StatelessResetKeyFile); err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
	if err != nil {
		return fmt.Errorf("load TLS certificate/key: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("TLS certificate is empty")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse TLS certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return fmt.Errorf("TLS certificate must use ECDSA P-256")
	}
	certPEM, err := os.ReadFile(c.TLS.Cert)
	if err != nil {
		return fmt.Errorf("read TLS certificate: %w", err)
	}
	if b, _ := pem.Decode(certPEM); b == nil {
		return fmt.Errorf("TLS certificate is not PEM encoded")
	}
	fmt.Println("configuration OK")
	return nil
}
