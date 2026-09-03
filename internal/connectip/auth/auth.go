package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func Fingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}
func PublicKeyBytes(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(ellipticMarshal(cert))
}
func ValidatePublicKeyString(s string) ([]byte, error) {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		return nil, e
	}
	if len(b) != 65 || b[0] != 4 {
		return nil, fmt.Errorf("expected uncompressed P-256 point")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), b)
	if x == nil || y == nil {
		return nil, fmt.Errorf("invalid P-256 point")
	}
	return b, nil
}
func ellipticMarshal(cert *x509.Certificate) []byte {
	if p, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		if p.Curve != elliptic.P256() {
			return nil
		}
		return elliptic.Marshal(elliptic.P256(), p.X, p.Y)
	}
	return nil
}
func Matches(cert *x509.Certificate, allowed []string) bool {
	got := PublicKeyBytes(cert)
	for _, want := range allowed {
		if got == want {
			return true
		}
	}
	return false
}
