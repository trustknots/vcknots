package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"sync"

	"github.com/go-jose/go-jose/v4"
)

// fixtureResponseEncryptionKey is the Verifier response encryption key every
// direct_post.jwt fixture advertises. Parsing refuses a direct_post.jwt request
// whose client_metadata leaves nothing to encrypt the response to
// (validateResponseEncryptionMetadata), so a fixture that uses the mode only to
// exercise something else carries this key. One key serves the whole package:
// no fixture decrypts a response with it.
var fixtureResponseEncryptionKey = sync.OnceValue(func() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
})

// responseEncryptionMetadata is Verifier metadata a HAIP direct_post.jwt
// request is admitted with: one P-256 ECDH-ES enc key and both content
// encryptions HAIP Section 5 requires the Verifier to list.
func responseEncryptionMetadata() *VerifierMetadata {
	return &VerifierMetadata{
		Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &fixtureResponseEncryptionKey().PublicKey, KeyID: "fixture-enc", Use: "enc", Algorithm: "ECDH-ES",
		}}},
		EncryptedResponseEncValuesSupported: []string{"A128GCM", "A256GCM"},
	}
}

// responseEncryptionClientMetadataParam is responseEncryptionMetadata as the
// JSON text of a client_metadata query parameter.
func responseEncryptionClientMetadataParam() string {
	encoded, err := json.Marshal(responseEncryptionMetadata())
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// responseEncryptionClientMetadataClaim is responseEncryptionMetadata as the
// JSON object of a client_metadata Request Object claim.
func responseEncryptionClientMetadataClaim() map[string]any {
	var claim map[string]any
	if err := json.Unmarshal([]byte(responseEncryptionClientMetadataParam()), &claim); err != nil {
		panic(err)
	}
	return claim
}
