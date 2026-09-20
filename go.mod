module github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified

go 1.26.0

toolchain go1.26.8

require (
	github.com/Piggy-Cat-bit-shadow/connect-ip-go v0.0.0-20260920163444-a3ff5f6ca9ce
	github.com/dunglas/httpsfv v1.1.1
	github.com/metacubex/http v0.1.7
	github.com/metacubex/quic-go v0.61.1-0.20260906020448-5dd41cf92b47
	github.com/metacubex/tls v0.1.8
	github.com/yosida95/uritemplate/v3 v3.0.2
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/net v0.56.0
	golang.org/x/sys v0.47.0
)

// Keep the pinned MetaCubeX QUIC API and HTTP/3 behavior. The replacement is
// a project-maintained fork carrying required DATAGRAM/ownership integration
// plus selected congestion-control support for the CONNECT-IP server.
replace github.com/metacubex/quic-go => github.com/Piggy-Cat-bit-shadow/quic-go v0.61.1-0.20260920163345-6c7a489285b3

require (
	github.com/metacubex/cpu v0.1.0 // indirect
	github.com/metacubex/hkdf v0.1.0 // indirect
	github.com/metacubex/hpke v0.1.0 // indirect
	github.com/metacubex/mlkem v0.1.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/text v0.40.0 // indirect
)
