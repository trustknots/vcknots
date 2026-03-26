module github.com/trustknots/vcknots/wallet/examples/server_integration_sdjwtkbjwt

go 1.24.5

require (
	github.com/go-jose/go-jose/v4 v4.1.3
	github.com/trustknots/vcknots/wallet v0.0.0
)

require (
	github.com/btcsuite/btcd/btcutil v1.1.6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.etcd.io/bbolt v1.4.3 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/text v0.3.3 // indirect
)

replace github.com/trustknots/vcknots/wallet => ../..
