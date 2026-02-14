module github.com/trustknots/vcknots/wallet/examples/custom_plugin

go 1.24.5

require github.com/trustknots/vcknots/wallet v0.0.0

require (
	github.com/btcsuite/btcd/btcutil v1.1.6 // indirect
	github.com/go-jose/go-jose/v4 v4.1.3 // indirect
)

replace github.com/trustknots/vcknots/wallet => ../..
