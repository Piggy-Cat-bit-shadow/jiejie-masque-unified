package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateServerCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	publicKey, err := generateServerCertificate(certPath, keyPath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatal("certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || cert.PublicKey.(*ecdsa.PublicKey).Curve != elliptic.P256() {
		t.Fatal("certificate key is not P-256 ECDSA")
	}
	publicDER, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(key) {
		t.Fatal("printed public key does not match certificate")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("private key is not PEM")
	}
	if _, err := x509.ParseECPrivateKey(keyBlock.Bytes); err != nil {
		t.Fatal(err)
	}
}
