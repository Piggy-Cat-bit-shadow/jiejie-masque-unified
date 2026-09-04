module github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified

go 1.25.0

require (
	github.com/Piggy-Cat-bit-shadow/connect-ip-go v0.0.0-20260904215559-39b8eb948ea5
	github.com/dunglas/httpsfv v1.0.2
	github.com/metacubex/http v0.1.7
	github.com/metacubex/quic-go v0.61.1-0.20260727080200-2548683b76f4
	github.com/metacubex/tls v0.1.8
	github.com/yosida95/uritemplate/v3 v3.0.2
	golang.org/x/sys v0.30.0
	gopkg.in/yaml.v3 v3.0.1
)

// Keep the pinned MetaCubeX QUIC API and HTTP/3 behavior. The replacement is
// a minimal fork at the same upstream commit which exposes native CUBIC for
// the CONNECT-IP server selector.
replace github.com/metacubex/quic-go => github.com/Piggy-Cat-bit-shadow/quic-go v0.0.0-20260904203815-027d7ce7fa01

require (
	github.com/metacubex/cpu v0.1.0 // indirect
	github.com/metacubex/hkdf v0.1.0 // indirect
	github.com/metacubex/hpke v0.1.0 // indirect
	github.com/metacubex/mlkem v0.1.0 // indirect
	github.com/metacubex/qpack v0.6.0 // indirect
	github.com/metacubex/randv2 v0.2.0 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/text v0.22.0 // indirect
)
