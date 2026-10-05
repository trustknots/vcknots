package acceptance

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
)

// credentialIssuerEntityType is the OpenID Federation Entity Type whose
// metadata is Credential Issuer Metadata (OpenID4VCI 1.0 §12.2.4, OpenID
// Federation 1.0 §5.1).
const credentialIssuerEntityType = "openid_credential_issuer"

// FederationIssuerKeys are the signing keys of a Credential Issuer that an
// OpenID Federation Trust Chain vouches for: the jwks of the
// openid_credential_issuer metadata derived from a validated Trust Chain
// (OpenID Federation 1.0 §5.2.1 "jwks", §6.1.4 metadata derivation). SD-JWT
// VC -19 §2.5 lets a separate specification define such a key discovery
// mechanism; Policy.Federation permits it for an https iss equal to EntityID.
//
// Only NewFederationIssuerKeys builds one, so the keys always come from a
// Trust Chain the federation package validated: resolve the chains with
// federation.Resolver.ResolveTrustChains (or validate a carried chain with
// federation.ValidateTrustChain) for the Credential Issuer, and pass one here.
type FederationIssuerKeys struct {
	entityID    string
	trustAnchor string
	expiresAt   time.Time
	keys        []jose.JSONWebKey
}

// NewFederationIssuerKeys takes the signing keys from the inline jwks of the
// openid_credential_issuer metadata that chain derives. The metadata must
// carry jwks; a signed_jwks_uri or jwks_uri is not retrieved. Keys whose use
// is not "sig", and private or symmetric keys, are not signing keys of the
// issuer and are dropped. Failures wrap ErrIssuerKeyUnresolved.
func NewFederationIssuerKeys(chain *federation.TrustChain) (*FederationIssuerKeys, error) {
	if chain == nil {
		return nil, fmt.Errorf("%w: no OpenID Federation Trust Chain", ErrIssuerKeyUnresolved)
	}
	metadata, err := federation.DeriveEntityMetadata(chain, credentialIssuerEntityType)
	if err != nil {
		return nil, fmt.Errorf("%w: %s metadata could not be derived from the Trust Chain: %w", ErrIssuerKeyUnresolved, credentialIssuerEntityType, err)
	}
	raw, present := metadata["jwks"]
	if !present {
		return nil, fmt.Errorf("%w: the %s metadata carries no jwks", ErrIssuerKeyUnresolved, credentialIssuerEntityType)
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: the %s jwks is not JSON: %w", ErrIssuerKeyUnresolved, credentialIssuerEntityType, err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(encoded, &set); err != nil {
		return nil, fmt.Errorf("%w: the %s jwks is not a JWK Set: %w", ErrIssuerKeyUnresolved, credentialIssuerEntityType, err)
	}
	keys := slices.DeleteFunc(set.Keys, func(key jose.JSONWebKey) bool {
		return !key.Valid() || !key.IsPublic() || (key.Use != "" && key.Use != "sig")
	})
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: the %s jwks carries no public signing key", ErrIssuerKeyUnresolved, credentialIssuerEntityType)
	}
	return &FederationIssuerKeys{
		entityID:    chain.SubjectEntityID,
		trustAnchor: chain.TrustAnchorEntityID,
		expiresAt:   chain.ExpiresAt,
		keys:        keys,
	}, nil
}

// EntityID is the Entity Identifier of the Credential Issuer the keys belong
// to: the credential's iss must equal it.
func (k *FederationIssuerKeys) EntityID() string { return k.entityID }

// TrustAnchor is the Entity Identifier of the Trust Anchor the chain ended at.
func (k *FederationIssuerKeys) TrustAnchor() string { return k.trustAnchor }

// ExpiresAt is the Trust Chain's expiry (OpenID Federation 1.0 §10.4). The
// keys authenticate no credential verified at or after it.
func (k *FederationIssuerKeys) ExpiresAt() time.Time { return k.expiresAt }

// Keys returns a copy of the signing keys.
func (k *FederationIssuerKeys) Keys() []jose.JSONWebKey { return slices.Clone(k.keys) }
