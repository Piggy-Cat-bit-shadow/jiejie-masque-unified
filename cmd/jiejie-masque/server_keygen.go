package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"
)

func serverKeygen(args []string) {
	fs := flag.NewFlagSet("server-keygen", flag.ExitOnError)
	certPath := fs.String("cert", "server.crt", "output certificate path")
	keyPath := fs.String("key", "server.key", "output private key path")
	_ = fs.Parse(args)
	publicKey, err := generateServerCertificate(*certPath, *keyPath, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "server-keygen:", err)
		os.Exit(1)
	}
	fmt.Println("certificate:", *certPath)
	fmt.Println("private-key-file:", *keyPath)
	fmt.Println("public-key:", publicKey)
}

func generateServerCertificate(certPath, keyPath string, now time.Time) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", err
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "masque-lite"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0600); err != nil {
		return "", err
	}
	if err := writePEM(certPath, "CERTIFICATE", certDER, 0644); err != nil {
		_ = os.Remove(keyPath)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(publicDER), nil
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}
