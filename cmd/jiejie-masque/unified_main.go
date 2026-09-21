package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
)

var version = "dev"
var commit = "unknown"
var connectIPGoCommit = "unknown"
var quicGoCommit = "unknown"
var buildTime = "unknown"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		if len(os.Args) > 2 && os.Args[2] == "--verbose" {
			fmt.Printf("jiejie-masque %s\nmain_commit=%s\nconnect_ip_go_commit=%s\nquic_go_commit=%s\nbuild_time=%s\ngo_version=%s\n", version, commit, connectIPGoCommit, quicGoCommit, buildTime, runtime.Version())
		} else {
			fmt.Printf("jiejie-masque %s commit=%s\n", version, commit)
		}
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
		field := fs.String("field", "", "field to output: tunnel-prefix, tunnel-address, tunnel-network, dns-port, or external-interface")
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
	if len(os.Args) > 1 && os.Args[1] == "doctor" {
		fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
		path := fs.String("config", "", "configuration file")
		if err := fs.Parse(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		if *path == "" {
			log.Fatal("--config is required")
		}
		c, err := config.Load(*path)
		if err != nil {
			log.Fatal(err)
		}
		if runDoctor(os.Stdout, c, defaultDoctorRuntime()) {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) < 2 {
		log.Fatal("usage: jiejie-masque serve|check-config|doctor|mihomo-config|network-prepare-info --config PATH")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	path := fs.String("config", "", "configuration file")
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
	if *path == "" {
		log.Fatal("--config is required")
	}
	if os.Args[1] == "check-config" {
		if err := checkConfig(*path); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("validation: pass\n")
		return
	}
	if os.Args[1] != "serve" {
		log.Fatalf("unknown command %q", os.Args[1])
	}
	if err := serveConnectIPArgs([]string{"--config", *path}); err != nil {
		log.Fatal(err)
	}
}
