package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"gopkg.in/yaml.v3"
)

func mihomoConfig(args []string) error {
	fs := flag.NewFlagSet("mihomo-config", flag.ContinueOnError)
	path := fs.String("config", "", "CONNECT-IP server configuration")
	server := fs.String("server", "", "public server hostname or address")
	port := fs.Int("port", 443, "public server UDP port")
	privateKey := fs.String("private-key", "", "client P-256 private key")
	name := fs.String("name", "MASQUE", "node name")
	sni := fs.String("sni", "", "optional TLS SNI")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *server == "" || *privateKey == "" || *port < 1 || *port > 65535 {
		return fmt.Errorf("--config, --server and --private-key are required; --port must be valid")
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	clients, err := c.ResolvedClients()
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(c.TLS.Cert)
	if err != nil {
		return err
	}
	certDER, err := decodeFirstCertificate(certPEM)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return fmt.Errorf("server certificate must use P-256 ECDSA")
	}
	serverPrefix, _ := parseTunnelAddress(c.Server.TunnelIPv4)
	node := map[string]any{
		"name": *name, "type": "masque", "server": *server, "port": *port,
		"private-key": *privateKey, "public-key": base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)),
		"ip": clients[0].TunnelIPv4.String(), "mtu": c.Server.MTU, "udp": true,
		"ip-stack":              map[string]any{"mode": "mips", "congestion-controller": "bbr3"},
		"congestion-controller": "bbr", "bbr-profile": "standard",
	}
	if *sni != "" {
		node["sni"] = *sni
	}
	if c.DNSGateway.IsEnabled() {
		node["remote-dns-resolve"] = true
		node["dns"] = []string{"udp://" + serverPrefix + ":" + strconv.Itoa(c.DNSGateway.Port)}
	}
	b, err := yaml.Marshal([]map[string]any{node})
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(b)
	return err
}

func decodeFirstCertificate(b []byte) ([]byte, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("server certificate PEM is invalid")
	}
	return block.Bytes, nil
}

func parseTunnelAddress(prefix string) (string, error) {
	for i := 0; i < len(prefix); i++ {
		if prefix[i] == '/' {
			return prefix[:i], nil
		}
	}
	return "", fmt.Errorf("invalid tunnel prefix")
}
