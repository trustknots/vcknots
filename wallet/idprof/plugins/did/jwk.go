package did

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/idprof/types"
)

// Sentinel errors the did:jwk method plugin returns.
var (
	// ErrDIDJWKIdentifierInvalid reports that the method-specific identifier is
	// not the base64url encoding of a public JWK: it does not decode, the
	// decoded bytes are not a JSON object, the object is not a key this library
	// understands, or it is a private or symmetric key.
	ErrDIDJWKIdentifierInvalid = common.NewCodedError("did_jwk_identifier_invalid", "did:jwk identifier does not encode a public JWK")
	// ErrDIDJWKOperationUnsupported reports an operation the did:jwk method
	// does not have. The identifier is the key, so there is nothing to publish
	// and nothing that can be changed without becoming a different DID.
	ErrDIDJWKOperationUnsupported = common.NewCodedError("did_jwk_operation_unsupported", "did:jwk profiles cannot be created or updated through this plugin")
)

// didJWKPrefix is the DID scheme and method name of the did:jwk method.
const didJWKPrefix = "did:jwk:"

// DIDJWKPlugin resolves did:jwk identifiers.
//
// The did:jwk method (https://github.com/quartzjer/did-jwk/blob/main/spec.md)
// carries the whole public key in the identifier: the method-specific
// identifier is the base64url encoding, without padding, of the JWK's JSON
// representation (RFC 7517). Resolution is therefore offline and deterministic
// - the identifier cannot name a key other than the one it encodes - and the
// document the method describes has exactly one verification method, whose
// identifier is the DID with the fragment "0".
//
// Only a public key resolves. A private or symmetric JWK in the identifier is
// refused rather than silently reduced to its public half, because publishing
// one is a mistake a resolver should report, not paper over.
type DIDJWKPlugin struct{}

// Create reports that did:jwk profiles are not created through this plugin.
// The identifier is a function of the key, so a caller that holds a key builds
// the identifier from it rather than asking a resolver to mint one.
func (p *DIDJWKPlugin) Create(opts ...types.CreateOption) (*types.IdentityProfile, error) {
	return nil, fmt.Errorf("%w: the identifier is derived from the key itself", ErrDIDJWKOperationUnsupported)
}

// Update reports that did:jwk profiles cannot be updated: changing the key
// changes the identifier, which makes it a different DID.
func (p *DIDJWKPlugin) Update(profile *types.IdentityProfile, opts ...types.UpdateOption) (*types.IdentityProfile, error) {
	return nil, fmt.Errorf("%w: a different key is a different did:jwk", ErrDIDJWKOperationUnsupported)
}

// Resolve decodes the public key the did:jwk identifier carries.
func (p *DIDJWKPlugin) Resolve(id string) (*types.IdentityProfile, error) {
	key, err := jwkFromDIDJWK(id)
	if err != nil {
		return nil, err
	}
	return &types.IdentityProfile{
		ID:     id,
		TypeID: IDProfileTypeID,
		Keys:   &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}},
	}, nil
}

// Validate reports whether profile is a well-formed did:jwk profile whose key
// is the one its identifier encodes. The comparison is possible offline, so it
// is made: a profile that disagrees with its own identifier is the one failure
// mode this method can have.
func (p *DIDJWKPlugin) Validate(profile *types.IdentityProfile) error {
	if profile == nil {
		return fmt.Errorf("%w: profile cannot be nil", types.ErrProfileValidation)
	}
	if profile.TypeID != IDProfileTypeID {
		return fmt.Errorf("%w: invalid type ID for did:jwk profile: %s", types.ErrProfileValidation, profile.TypeID)
	}
	encoded, err := jwkFromDIDJWK(profile.ID)
	if err != nil {
		return err
	}
	if profile.Keys == nil || len(profile.Keys.Keys) != 1 {
		return fmt.Errorf("%w: did:jwk profile must carry exactly one key", types.ErrInvalidKeys)
	}
	expected, err := encoded.Thumbprint(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("%w: identifier key has no thumbprint", types.ErrInvalidKeys)
	}
	present := profile.Keys.Keys[0]
	actual, err := present.Thumbprint(crypto.SHA256)
	if err != nil || !bytes.Equal(expected, actual) {
		return fmt.Errorf("%w: key material does not match the did:jwk identifier", types.ErrInvalidKeys)
	}
	return nil
}

// jwkFromDIDJWK decodes the public key a did:jwk identifier carries.
func jwkFromDIDJWK(id string) (jose.JSONWebKey, error) {
	if !strings.HasPrefix(id, didJWKPrefix) {
		return jose.JSONWebKey{}, fmt.Errorf("%w: %q is not a did:jwk identifier", ErrDIDJWKIdentifierInvalid, id)
	}
	encoded := strings.TrimPrefix(id, didJWKPrefix)
	if encoded == "" {
		return jose.JSONWebKey{}, fmt.Errorf("%w: method-specific identifier is empty", ErrDIDJWKIdentifierInvalid)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		// The method specification writes the identifier without padding, but
		// a padded identifier decodes to the same key and refusing it would
		// only reject an interoperable peer over a formatting detail.
		decoded, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			return jose.JSONWebKey{}, fmt.Errorf("%w: identifier is not base64url", ErrDIDJWKIdentifierInvalid)
		}
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(decoded, &probe); err != nil || probe == nil {
		return jose.JSONWebKey{}, fmt.Errorf("%w: identifier does not encode a JSON object", ErrDIDJWKIdentifierInvalid)
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(decoded); err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("%w: identifier does not encode a usable JWK", ErrDIDJWKIdentifierInvalid)
	}
	if !key.Valid() || !key.IsPublic() {
		return jose.JSONWebKey{}, fmt.Errorf("%w: identifier does not encode a public key", ErrDIDJWKIdentifierInvalid)
	}
	// The did:jwk method gives the single verification method the fragment "0",
	// so a JWS that names it as its `kid` names this key.
	key.KeyID = id + "#0"
	return key, nil
}
