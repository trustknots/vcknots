package issuerkeys

import (
	"encoding/json"

	"github.com/go-jose/go-jose/v4"
)

// maximumX5CChainLength bounds a presented certification path. RFC 5280
// section 6 path building has no legitimate use for a longer one, and refusing
// an oversized chain before anything is parsed keeps one header from buying an
// attacker unbounded certificate parsing.
const maximumX5CChainLength = 16

// x5cChain returns the certification path of a credential JWT's `x5c` header,
// or nothing when the header is absent, empty, longer than the cap, or carries
// an empty entry.
//
// Nothing here judges the path. Deciding whether it reaches a trust anchor is a
// separate question from deciding which key a credential claims to be signed
// with, and this package answers only the second.
func x5cChain(values []string) []string {
	if len(values) == 0 || len(values) > maximumX5CChainLength {
		return nil
	}
	for _, value := range values {
		if value == "" {
			return nil
		}
	}
	return values
}

// algCompatibleKeys returns the keys of a JWK Set that could have produced a
// signature made with alg.
//
// A key whose `use` is not "sig" is never a signature key (RFC 7517 section
// 4.2). `alg` is an optional hint (section 4.4), so a key that states none stays
// a candidate; a key that states a different one is dropped. An empty result is
// an error, so a caller can tell "no key at all" from "no key for this
// algorithm".
func algCompatibleKeys(set *jose.JSONWebKeySet, alg string) ([]jose.JSONWebKey, error) {
	if set == nil || len(set.Keys) == 0 {
		return nil, newMechanismError(ErrIssuerMetadataInvalid, "issuer metadata carries no signing key")
	}
	compatible := make([]jose.JSONWebKey, 0, len(set.Keys))
	for _, key := range set.Keys {
		public, ok := publicKey(key)
		if !ok {
			continue
		}
		if !isSignatureKey(public) {
			continue
		}
		if alg == "" || public.Algorithm == "" || public.Algorithm == alg {
			compatible = append(compatible, public)
		}
	}
	if len(compatible) == 0 {
		return nil, newMechanismError(ErrIssuerMetadataInvalid, "no issuer metadata key matches the credential algorithm")
	}
	return compatible, nil
}

// isSignatureKey reports whether key may verify a signature: a key that
// declares a `use` other than "sig" (RFC 7517 section 4.2) may not.
func isSignatureKey(key jose.JSONWebKey) bool {
	return key.Use == "" || key.Use == "sig"
}

// publicKey returns the public half of key, or false when key carries no usable
// asymmetric key.
//
// A key set handed to the resolver is caller input, and a caller that pasted a
// private JWK into issuer metadata has published a mistake rather than a
// different key: its public half is the key that verifies. A symmetric key has
// no public half and cannot authenticate an issuer to a party that does not
// already share the secret, so it is dropped.
func publicKey(key jose.JSONWebKey) (jose.JSONWebKey, bool) {
	if key.Key == nil || !key.Valid() {
		return jose.JSONWebKey{}, false
	}
	if key.IsPublic() {
		return key, true
	}
	public := key.Public()
	if !public.Valid() || !public.IsPublic() {
		return jose.JSONWebKey{}, false
	}
	return public, true
}

// orderByKeyID puts the keys whose `kid` equals keyID first and keeps the rest
// behind them.
//
// Nothing is dropped. A `kid` is a hint, and an issuer that rotates a key
// without updating the credentials it already signed - or that publishes a
// `kid` under a different spelling - leaves a credential whose `kid` names no
// published key while a published key still verifies it. Ordering makes the
// named key cheap to try first; dropping the others would make the credential
// unverifiable over a naming detail.
func orderByKeyID(keys []jose.JSONWebKey, keyID string) []jose.JSONWebKey {
	if keyID == "" {
		return keys
	}
	ordered := make([]jose.JSONWebKey, 0, len(keys))
	for _, key := range keys {
		if key.KeyID == keyID {
			ordered = append(ordered, key)
		}
	}
	for _, key := range keys {
		if key.KeyID != keyID {
			ordered = append(ordered, key)
		}
	}
	return ordered
}

// parseJWKSet reads a JWK Set (RFC 7517 section 5) from a JSON document.
//
// Keys this library cannot represent are skipped rather than failing the set: a
// set may legitimately carry a key for an algorithm outside this library's
// reach, and one such entry must not make the issuer's usable keys
// unreachable. A set with no readable key at all is an error.
func parseJWKSet(document json.RawMessage) (*jose.JSONWebKeySet, error) {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(document, &raw); err != nil {
		return nil, newMechanismError(ErrIssuerMetadataInvalid, "jwks is not a JWK Set")
	}
	set := &jose.JSONWebKeySet{}
	for _, entry := range raw.Keys {
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON(entry); err != nil {
			continue
		}
		if !key.Valid() || !key.IsPublic() {
			continue
		}
		set.Keys = append(set.Keys, key)
	}
	if len(set.Keys) == 0 {
		return nil, newMechanismError(ErrIssuerMetadataInvalid, "jwks carries no readable public key")
	}
	return set, nil
}
