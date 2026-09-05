package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"gopkg.in/yaml.v3"
)

func mihomoConfig(args []string) error {
	return mihomoConfigTo(os.Stdout, args)
}

func mihomoConfigTo(out io.Writer, args []string) error {
	fs := flag.NewFlagSet("mihomo-config", flag.ContinueOnError)
	path := fs.String("config", "", "CONNECT-IP server configuration")
	server := fs.String("server", "", "public server hostname or address")
	port := fs.Int("port", 443, "public server UDP port")
	privateKey := fs.String("private-key", "", "client P-256 private key")
	clientName := fs.String("client", "", "configured client name to validate/select; private key must belong to it")
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
	clientPublicKey, err := clientPublicKeyFromPrivateKey(*privateKey)
	if err != nil {
		return err
	}
	client, err := selectMihomoClient(clients, clientPublicKey, *clientName)
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
		"ip": client.TunnelIPv4.String(), "mtu": c.Server.MTU, "udp": true,
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
	_, err = out.Write(b)
	return err
}

func clientPublicKeyFromPrivateKey(encoded string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("invalid client private key: base64 encoding")
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		parsed, pkcs8Err := x509.ParsePKCS8PrivateKey(der)
		if pkcs8Err != nil {
			return "", fmt.Errorf("invalid client private key: DER encoding")
		}
		var ok bool
		key, ok = parsed.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("invalid client private key: expected ECDSA key")
		}
	}
	if key.Curve == nil || key.Curve.Params() == nil || key.Curve.Params().Name != elliptic.P256().Params().Name || key.Curve.Params().BitSize != elliptic.P256().Params().BitSize {
		return "", fmt.Errorf("invalid client private key: expected P-256 ECDSA key")
	}
	public := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	return base64.StdEncoding.EncodeToString(public), nil
}

func selectMihomoClient(clients []config.ResolvedClient, publicKey, clientName string) (config.ResolvedClient, error) {
	if clientName != "" {
		foundName := false
		for _, client := range clients {
			if client.Name == clientName {
				foundName = true
				break
			}
		}
		if !foundName {
			return config.ResolvedClient{}, fmt.Errorf("configured client %q not found", clientName)
		}
	}

	matches := make([]config.ResolvedClient, 0, 1)
	for _, client := range clients {
		if clientName != "" && client.Name != clientName {
			continue
		}
		for _, key := range client.PublicKeys {
			if key == publicKey {
				matches = append(matches, client)
				break
			}
		}
	}
	if len(matches) == 0 {
		return config.ResolvedClient{}, fmt.Errorf("client private key does not match any configured client")
	}
	if len(matches) > 1 {
		return config.ResolvedClient{}, fmt.Errorf("client private key matches multiple configured clients")
	}
	return matches[0], nil
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
