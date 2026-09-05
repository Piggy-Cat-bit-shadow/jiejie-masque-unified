package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectudp"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/notify"
	"gopkg.in/yaml.v3"
)

type modeEnvelope struct {
	Mode string `yaml:"mode"`
}

var version = "0.1.0"
var commit = "unknown"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("jiejie-masque %s commit=%s\n", version, commit)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("jiejie-masque %s commit=%s\n", version, commit)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		keygen()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "server-keygen" {
		serverKeygen(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "mihomo-config" {
		if err := mihomoConfig(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "network-prepare-info" {
		fs := flag.NewFlagSet("network-prepare-info", flag.ContinueOnError)
		path := fs.String("config", "", "configuration file")
		field := fs.String("field", "", "field to output: tunnel-prefix or external-interface")
		if err := fs.Parse(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		if *path == "" {
			log.Fatal("--config is required")
		}
		if err := networkPrepareInfo(os.Stdout, *path, *field); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) < 2 {
		log.Fatal("usage: jiejie-masque serve|check-config|mihomo-config|network-prepare-info --config PATH")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	path := fs.String("config", "", "configuration file")
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
	if *path == "" {
		log.Fatal("--config is required")
	}
	b, err := os.ReadFile(*path)
	if err != nil {
		log.Fatal(err)
	}
	var env modeEnvelope
	if err := yaml.Unmarshal(b, &env); err != nil {
		log.Fatal(err)
	}
	if strings.TrimSpace(env.Mode) == "connect-udp" {
		c, err := connectudp.Load(*path)
		if err != nil {
			log.Fatal(err)
		}
		if os.Args[1] == "check-config" {
			if err := c.Validate(true); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("mode: connect-udp\nvalidation: pass\n")
			return
		}
		if os.Args[1] != "serve" {
			log.Fatalf("unknown command %q", os.Args[1])
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		ready := make(chan string, 1)
		serveErr := make(chan error, 1)
		go func() { serveErr <- connectudp.ServeContextReady(ctx, c, ready) }()
		select {
		case addr := <-ready:
			log.Printf("CONNECT-UDP ready on %s", addr)
			if err := notify.Send("READY=1"); err != nil {
				log.Printf("systemd notify failed: %v", err)
			}
			go runSystemdWatchdog(ctx)
		case err := <-serveErr:
			if err != nil {
				log.Fatal(err)
			}
			return
		}
		if err := <-serveErr; err != nil {
			log.Fatal(err)
		}
		return
	}
	if strings.TrimSpace(env.Mode) != "connect-ip" {
		log.Fatalf("unsupported mode %q", env.Mode)
	}
	if os.Args[1] == "check-config" {
		if err := checkConfig(*path); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("mode: connect-ip\nvalidation: pass\n")
		return
	}
	if os.Args[1] != "serve" {
		log.Fatalf("unknown command %q", os.Args[1])
	}
	// The migrated CONNECT-IP runner retains its validated legacy flag parser.
	os.Args = []string{os.Args[0], "--config", *path}
	if err := serveConnectIP(); err != nil {
		log.Fatal(err)
	}
}
