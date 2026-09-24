module github.com/trustknots/vcknots/wallet/examples/custom_plugin

go 1.25.0

require github.com/trustknots/vcknots/wallet v0.0.0

require (
	github.com/btcsuite/btcd/btcutil v1.2.0 // indirect
	github.com/cayleygraph/quad v1.3.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	github.com/piprate/json-gold v0.8.0 // indirect
	github.com/pquerna/cachecontrol v0.2.0 // indirect
	golang.org/x/crypto v0.53.0 // indirect
)

replace github.com/trustknots/vcknots/wallet => ../..
