module github.com/trustknots/vcknots/wallet/examples/server_integration_jwtvc

go 1.25.0

require github.com/trustknots/vcknots/wallet v0.0.0

require (
	github.com/btcsuite/btcd/btcutil v1.2.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.etcd.io/bbolt v1.5.0 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.39.0 // indirect
)

replace github.com/trustknots/vcknots/wallet => ../..
