package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"gopkg.in/yaml.v3"
)

func TestMihomoConfigSelectsSecondClientByPrivateKey(t *testing.T) {
	_, publicA, err := generateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	privateB, publicB, err := generateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	certPath := writeTestServerCertificate(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	config := "mode: connect-ip\n" +
		"listen: 127.0.0.1:4434\n" +
		"tls:\n  cert: " + certPath + "\n  key: unused\n" +
		"server:\n  tunnel_ipv4: 10.200.0.1/24\n  mtu: 1280\n" +
		"dns_gateway:\n  enabled: false\n" +
		"clients:\n" +
		"  - name: iphone\n    public_key: " + publicA + "\n    tunnel_ipv4: 10.200.0.2/32\n" +
		"  - name: mac\n    public_key: " + publicB + "\n    tunnel_ipv4: 10.200.0.3/32\n"
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := mihomoConfigTo(&output, []string{"--config", configPath, "--server", "example.com", "--private-key", privateB}); err != nil {
		t.Fatal(err)
	}
	var nodes []map[string]any
	if err := yaml.Unmarshal(output.Bytes(), &nodes); err != nil {
		t.Fatal(err)
	}
	if got := nodes[0]["ip"]; got != "10.200.0.3/32" {
		t.Fatalf("selected wrong client IP: got %v, want %s", got, "10.200.0.3/32")
	}
	if got := nodes[0]["private-key"]; got != privateB {
		t.Fatalf("private key was changed: got %v", got)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := decodeFirstCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic := cert.PublicKey.(*ecdsa.PublicKey)
	wantServerPublic := base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), serverPublic.X, serverPublic.Y))
	if got := nodes[0]["public-key"]; got != wantServerPublic {
		t.Fatalf("server public key changed: got %v, want %s", got, wantServerPublic)
	}

	var selectedClientOutput bytes.Buffer
	err = mihomoConfigTo(&selectedClientOutput, []string{"--config", configPath, "--server", "example.com", "--private-key", privateB, "--client", "iphone"})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("client selector mismatch was not rejected: %v", err)
	}
	err = mihomoConfigTo(&selectedClientOutput, []string{"--config", configPath, "--server", "example.com", "--private-key", privateB, "--client", "missing"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown client selector was not rejected: %v", err)
	}
}

func TestMihomoConfigPrivateKeyFormatsAndFailures(t *testing.T) {
	privateKey, _, err := generateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientPublicKeyFromPrivateKey("not-base64"); err == nil {
		t.Fatal("invalid base64 was accepted")
	}
	if _, err := clientPublicKeyFromPrivateKey(base64.StdEncoding.EncodeToString([]byte("invalid DER"))); err == nil {
		t.Fatal("invalid DER was accepted")
	}
	publicKey, err := clientPublicKeyFromPrivateKey(privateKey)
	if err != nil || publicKey == "" {
		t.Fatalf("SEC1 P-256 key was rejected: %v", err)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := x509.MarshalECPrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientPublicKeyFromPrivateKey(base64.StdEncoding.EncodeToString(p384DER)); err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("non-P256 key was not rejected: %v", err)
	}

	parsed, err := x509.ParseECPrivateKey(mustBase64Decode(t, privateKey))
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientPublicKeyFromPrivateKey(base64.StdEncoding.EncodeToString(pkcs8DER)); err != nil {
		t.Fatalf("PKCS#8 P-256 key was rejected: %v", err)
	}
	if _, err := clientPublicKeyFromPrivateKey(privateKey + "="); err == nil {
		t.Fatal("malformed private key was accepted")
	}
}

func TestSelectMihomoClientUsesDerivedIdentity(t *testing.T) {
	privateA, publicA, err := generateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	privateB, publicB, err := generateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	clients := []config.ResolvedClient{
		{Name: "iphone", PublicKeys: []string{publicA}, TunnelIPv4: netip.MustParsePrefix("10.200.0.2/32")},
		{Name: "mac", PublicKeys: []string{publicB}, TunnelIPv4: netip.MustParsePrefix("10.200.0.3/32")},
	}
	derivedA, err := clientPublicKeyFromPrivateKey(privateA)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := selectMihomoClient(clients, derivedA, "")
	if err != nil || selected.TunnelIPv4.String() != "10.200.0.2/32" {
		t.Fatalf("single-client identity selection failed: %+v, %v", selected, err)
	}
	derivedB, err := clientPublicKeyFromPrivateKey(privateB)
	if err != nil {
		t.Fatal(err)
	}
	selected, err = selectMihomoClient(clients, derivedB, "mac")
	if err != nil || selected.TunnelIPv4.String() != "10.200.0.3/32" {
		t.Fatalf("explicit client selection failed: %+v, %v", selected, err)
	}
	if _, err := selectMihomoClient(clients, derivedB, "iphone"); err == nil {
		t.Fatal("client selector accepted a mismatched private key")
	}
	if _, err := selectMihomoClient(clients, derivedB, "unknown"); err == nil {
		t.Fatal("unknown client selector was accepted")
	}

	shared := []config.ResolvedClient{{Name: "shared", PublicKeys: []string{publicA, publicB}, TunnelIPv4: netip.MustParsePrefix("10.200.0.4/32")}}
	selected, err = selectMihomoClient(shared, derivedB, "")
	if err != nil || selected.TunnelIPv4.String() != "10.200.0.4/32" {
		t.Fatalf("multiple public keys did not resolve to one client: %+v, %v", selected, err)
	}
	if _, err := selectMihomoClient(clients[:1], derivedB, ""); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unknown private key was not rejected: %v", err)
	}
}

func mustBase64Decode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func writeTestServerCertificate(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: new(big.Int).SetInt64(1), Subject: pkix.Name{CommonName: "example.com"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: []string{"example.com"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "server.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
