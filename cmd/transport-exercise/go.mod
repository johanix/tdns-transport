module github.com/johanix/tdns-transport/cmd/transport-exercise

go 1.25.2

replace (
	github.com/johanix/tdns-transport/v2 => ../../v2
	github.com/johanix/tdns/v2/core => ../../../tdns/v2/core
	github.com/johanix/tdns/v2/edns0 => ../../../tdns/v2/edns0
)

require (
	github.com/johanix/tdns-transport/v2 v2.0.0-00010101000000-000000000000
	github.com/miekg/dns v1.1.70
)

require (
	github.com/go-jose/go-jose/v4 v4.0.5 // indirect
	github.com/johanix/tdns/v2/core v0.0.0-20251215204415-08e1f7d4ef39 // indirect
	github.com/johanix/tdns/v2/edns0 v0.0.0-00010101000000-000000000000 // indirect
	github.com/quic-go/quic-go v0.58.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
)
