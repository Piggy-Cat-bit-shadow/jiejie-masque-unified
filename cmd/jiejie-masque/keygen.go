package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

func keygen() {
	privateKey, publicKey, err := generateClientKey()
	if err != nil {
		panic(err)
	}
	fmt.Printf("private-key: %s\npublic-key: %s\n", privateKey, publicKey)
}

func generateClientKey() (privateKey, publicKey string, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	privateDER, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return "", "", err
	}
	public := elliptic.Marshal(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
	return base64.StdEncoding.EncodeToString(privateDER), base64.StdEncoding.EncodeToString(public), nil
}
