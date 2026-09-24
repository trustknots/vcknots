// Package attestation obtains and validates the attestations an OpenID4VCI
// wallet presents: the Wallet (Client) Attestation of
// draft-ietf-oauth-attestation-based-client-auth (OpenID4VCI 1.0 Appendix E,
// HAIP §4.4.1) and the key attestation of OpenID4VCI 1.0 Appendix D (HAIP
// §4.5.1).
package attestation

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/internal/jwtproof"
	"github.com/trustknots/vcknots/wallet/keystore"
)

// JWT typ values of the two attestations.
const (
	clientAttestationType = jwtproof.TypeClientAttestation // oauth-client-attestation+jwt
	keyAttestationType    = jwtproof.TypeKeyAttestation    // key-attestation+jwt
)

// ClientProvider obtains a Wallet Attestation for this wallet instance. The
// library never handles the attester's private key.
type ClientProvider interface {
	ClientAttestation(ctx context.Context, request ClientRequest) (*ClientAttestation, error)
}

// ClientRequest is the input to a ClientProvider. AuthorizationServer lets the
// provider scope the attestation to one server: "Wallet Attestations MUST NOT
// be reused across different Issuers" (HAIP §4.4.1).
type ClientRequest struct {
	ClientID            string
	ClientKey           jose.JSONWebKey // wallet instance public key (cnf.jwk)
	AuthorizationServer string          // issuer identifier the attestation is used with
}

// ClientAttestation is a provider-issued Client Attestation JWT.
type ClientAttestation struct {
	JWT string
	// ExpiresAt, when set, ends the attestation's use before its exp claim.
	ExpiresAt time.Time
}

// KeyProvider obtains a key attestation for holder keys.
type KeyProvider interface {
	KeyAttestation(ctx context.Context, request KeyRequest) (*KeyAttestation, error)
}

// KeyRequest is the input to a KeyProvider. It is JSON-serializable so a
// provider may live in another process; Keys are public keys only.
type KeyRequest struct {
	Keys     []jose.JSONWebKey `json:"keys"`     // holder keys to attest, in proof order
	Nonce    string            `json:"nonce"`    // c_nonce when the issuer provides one
	Audience string            `json:"audience"` // credential issuer identifier; checked against a present aud
}

// KeyAttestation is a provider-issued key-attestation+jwt.
type KeyAttestation struct {
	JWT string
	// ExpiresAt, when set, ends the attestation's use before its exp claim.
	ExpiresAt time.Time
}

// StaticClientAttester self-issues Wallet Attestations with a local attester
// key, for tests and single-operator deployments.
type StaticClientAttester struct {
	Key      keystore.KeyEntry
	Chain    []*x509.Certificate // x5c, leaf first; HAIP requires it
	Issuer   string
	Lifetime time.Duration // zero means five minutes
}

// StaticKeyAttester self-issues key attestations with a local attester key,
// for tests and single-operator deployments.
type StaticKeyAttester struct {
	Key      keystore.KeyEntry
	Chain    []*x509.Certificate // x5c, leaf first; HAIP requires it
	Issuer   string
	Lifetime time.Duration // zero means five minutes
}

var (
	_ ClientProvider = (*StaticClientAttester)(nil)
	_ KeyProvider    = (*StaticKeyAttester)(nil)
)

// ClientAttestation returns a JWT with iss = Issuer, sub = the client_id,
// cnf.jwk = the client key and aud = the authorization server when named.
func (a *StaticClientAttester) ClientAttestation(ctx context.Context, request ClientRequest) (*ClientAttestation, error) {
	if a == nil || a.Key == nil {
		return nil, errors.New("static client attester key is required")
	}
	if request.ClientKey.Key == nil {
		return nil, errors.New("client key is required")
	}
	lifetime := effectiveLifetime(a.Lifetime)
	now := time.Now()
	token, err := jwtproof.ClientAttestation(ctx, a.Key, jwtproof.ClientAttestationOptions{
		Issuer:    a.Issuer,
		ClientID:  request.ClientID,
		ClientKey: request.ClientKey,
		Audience:  strings.TrimSpace(request.AuthorizationServer),
		Chain:     a.Chain,
		Lifetime:  lifetime,
	})
	if err != nil {
		return nil, err
	}
	return &ClientAttestation{JWT: token, ExpiresAt: now.Add(lifetime)}, nil
}

// KeyAttestation returns a JWT listing every requested key in attested_keys,
// with nonce set to the c_nonce when given (OpenID4VCI 1.0 Appendix D.1).
func (a *StaticKeyAttester) KeyAttestation(ctx context.Context, request KeyRequest) (*KeyAttestation, error) {
	if a == nil || a.Key == nil {
		return nil, errors.New("static key attester key is required")
	}
	for index := range request.Keys {
		if request.Keys[index].Key == nil {
			return nil, fmt.Errorf("holder key at index %d is missing a key", index)
		}
	}
	token, err := jwtproof.KeyAttestation(ctx, a.Key, jwtproof.KeyAttestationOptions{
		Issuer:       a.Issuer,
		AttestedKeys: request.Keys,
		Nonce:        request.Nonce,
		Chain:        a.Chain,
		Lifetime:     a.Lifetime,
	})
	if err != nil {
		return nil, err
	}
	return &KeyAttestation{JWT: token}, nil
}

func effectiveLifetime(lifetime time.Duration) time.Duration {
	if lifetime <= 0 {
		return jwtproof.DefaultLifetime
	}
	return lifetime
}
