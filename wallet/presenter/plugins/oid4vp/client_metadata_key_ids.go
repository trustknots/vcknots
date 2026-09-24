package oid4vp

import (
	"encoding/json"
	"fmt"
)

// validateClientMetadataJWKKeyIDs applies OpenID4VP 1.0 Section 5.1 to the
// client_metadata parameter of one Authorization Request: "Each JWK in the set
// MUST have a `kid` (Key ID) parameter that uniquely identifies the key within
// the context of the request."
//
// It reads the parameter as the Verifier sent it rather than the decoded
// VerifierMetadata, because the decode keeps only the keys this library can
// use (RFC 7517 Section 5) and the rule covers every JWK in the set. A member
// that is not an object, or whose kid is absent, empty or not a string, has no
// kid. Metadata without jwks carries no key the rule applies to.
//
// The check runs only when the presenter sets RequireClientMetadataJWKKeyIDs;
// see that field for why it is not always on.
func validateClientMetadataJWKKeyIDs(rawMetadata []byte) error {
	var metadata struct {
		Jwks *struct {
			Keys []json.RawMessage `json:"keys"`
		} `json:"jwks"`
	}
	if err := json.Unmarshal(rawMetadata, &metadata); err != nil {
		// The same bytes decoded as VerifierMetadata before this check runs,
		// so a failure here is not reachable; refuse rather than pass.
		return fmt.Errorf("client_metadata.jwks could not be read: %w", ErrClientMetadataJWKKeyIDMissing)
	}
	if metadata.Jwks == nil {
		return nil
	}
	seen := make(map[string]int, len(metadata.Jwks.Keys))
	for index, rawKey := range metadata.Jwks.Keys {
		var key map[string]any
		if err := json.Unmarshal(rawKey, &key); err != nil || key == nil {
			return fmt.Errorf("client_metadata.jwks.keys[%d] is not a JWK with a kid: %w", index, ErrClientMetadataJWKKeyIDMissing)
		}
		keyID, ok := key["kid"].(string)
		if !ok || keyID == "" {
			return fmt.Errorf("client_metadata.jwks.keys[%d] has no kid: %w", index, ErrClientMetadataJWKKeyIDMissing)
		}
		if first, duplicate := seen[keyID]; duplicate {
			return fmt.Errorf("client_metadata.jwks.keys[%d] repeats the kid of keys[%d]: %w", index, first, ErrClientMetadataJWKKeyIDDuplicate)
		}
		seen[keyID] = index
	}
	return nil
}
