package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/auth"
)

func TestGenerateClientKeyUsesSEC1DER(t *testing.T) {
	privateKey, publicKey, err := generateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseECPrivateKey(privateDER)
	if err != nil {
		t.Fatalf("private key is not SEC1 DER: %v", err)
	}
	if parsed.Curve != elliptic.P256() {
		t.Fatal("private key is not P-256")
	}
	public, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	want := elliptic.Marshal(elliptic.P256(), parsed.PublicKey.X, parsed.PublicKey.Y)
	if string(public) != string(want) {
		t.Fatal("public key does not match parsed private key")
	}
	if len(public) != 65 || public[0] != 4 {
		t.Fatal("public key is not uncompressed P-256")
	}
	if !auth.Matches(&x509.Certificate{PublicKey: &parsed.PublicKey}, []string{publicKey}) {
		t.Fatal("public key is not accepted by the client whitelist format")
	}
	rawScalar := make([]byte, 32)
	parsed.D.FillBytes(rawScalar)
	if _, err := x509.ParseECPrivateKey(rawScalar); err == nil {
		t.Fatal("raw private scalar unexpectedly parsed as SEC1 DER")
	}
}
