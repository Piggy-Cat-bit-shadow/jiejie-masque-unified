package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func TestMatchesPublicKey(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	c := &x509.Certificate{RawSubjectPublicKeyInfo: der, PublicKey: &k.PublicKey}
	w := PublicKeyBytes(c)
	if !Matches(c, []string{w}) || Matches(c, []string{"bad"}) {
		t.Fatal("public key matching failed")
	}
}
