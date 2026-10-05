package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/trustknots/vcknots/wallet/keystore"
)

// IKeyEntry is a signing key: every holder, DPoP, client authentication and
// attester key the wallet uses. Sign signs the input bytes; ECDSA
// implementations may return DER-encoded ASN.1 or raw IEEE P1363 (R || S)
// signatures. PublicKey returns the public JWK only, and its alg member selects
// the JWS algorithm (an RSA key must set it).
//
// IKeyEntry has the method set of keystore.KeyEntry, so values convert both
// ways. A key held in a hardware module or remote signer may also implement
// keystore.ContextSigner to receive the operation's context.
type IKeyEntry interface {
	ID() string
	PublicKey() jose.JSONWebKey
	Sign(data []byte) ([]byte, error)
}

var (
	_ keystore.KeyEntry = IKeyEntry(nil)
	_ IKeyEntry         = keystore.KeyEntry(nil)
)

type inMemoryECKeyEntry struct {
	id      string
	privKey *ecdsa.PrivateKey
	pubJWK  jose.JSONWebKey
}

func newInMemoryECKeyEntry() (*inMemoryECKeyEntry, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	id := uuid.NewString()
	pubJWK := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     id,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	return &inMemoryECKeyEntry{
		id:      id,
		privKey: privKey,
		pubJWK:  pubJWK,
	}, nil
}
func (k *inMemoryECKeyEntry) ID() string {
	return k.id
}
func (k *inMemoryECKeyEntry) PublicKey() jose.JSONWebKey {
	return k.pubJWK
}
func (k *inMemoryECKeyEntry) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, k.privKey, digest[:])
}
