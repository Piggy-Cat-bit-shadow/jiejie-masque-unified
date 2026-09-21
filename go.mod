module github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified

go 1.26.0

toolchain go1.26.8

require (
	github.com/metacubex/quic-go v0.61.1-0.20260921033412-327d53433eaf
	github.com/metacubex/tls v0.1.8
	github.com/yosida95/uritemplate/v3 v3.0.2
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/sys v0.47.0
)

require (
	github.com/metacubex/http v0.1.7 // indirect
	github.com/metacubex/qpack v0.6.0 // indirect
	github.com/metacubex/randv2 v0.2.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
)

// Keep the upstream module paths and HTTP/3 API while consuming the clean
// project-maintained candidates for the minimal BBR/runtime port.
replace github.com/metacubex/quic-go => github.com/Piggy-Cat-bit-shadow/quic-go v0.61.1-0.20260921033552-d8f5ba022f1e

require (
	github.com/dunglas/httpsfv v1.1.1 // indirect
	github.com/metacubex/connect-ip-go v0.0.0-20260727083417-67ccdb0cf771
	github.com/metacubex/cpu v0.1.0 // indirect
	github.com/metacubex/hkdf v0.1.0 // indirect
	github.com/metacubex/hpke v0.1.0 // indirect
	github.com/metacubex/mlkem v0.1.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

replace github.com/metacubex/connect-ip-go => github.com/Piggy-Cat-bit-shadow/connect-ip-go v0.0.0-20260727083417-67ccdb0cf771
