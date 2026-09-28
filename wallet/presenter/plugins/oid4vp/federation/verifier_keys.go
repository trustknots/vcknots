package federation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
)

// Media types and typ of the JWK Set representations of OpenID Federation 1.0
// Section 5.2.1.
const (
	signedJWKSMediaType = "application/jwk-set+jwt"
	signedJWKSTyp       = "jwk-set+jwt"
	jwkSetMediaType     = "application/jwk-set+json"
)

// verifierRequestObjectKeys returns the keys the Verifier signs Request
// Objects with. OpenID Federation 1.0 Section 12.1.1.1.2: the Wallet "MUST
// verify that the client was actually the one sending the Authentication
// Request by verifying the signature of the Request Object using the key
// material the client published in its metadata" for its Entity Type, here
// openid_credential_verifier. Section 5.2.1 names three representations of
// that key material and states that it is distinct from the Federation Entity
// Keys in the Entity Statement's jwks claim, which therefore never verify a
// Request Object.
//
// jwks is read first, since it is recorded in the validated Trust Chain, then
// signed_jwks_uri, whose JWT must be signed with a Federation Entity Key of
// the Verifier, then jwks_uri. Keys whose use is not sig are left out.
func (r *Resolver) verifierRequestObjectKeys(ctx context.Context, chain *TrustChain, metadata map[string]any) (jose.JSONWebKeySet, error) {
	if raw, present := metadata["jwks"]; present {
		set, err := metadataJWKS(raw, "jwks")
		if err != nil {
			return jose.JSONWebKeySet{}, err
		}
		return signingKeys(set)
	}
	if raw, present := metadata["signed_jwks_uri"]; present {
		location, ok := raw.(string)
		if !ok {
			return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "signed_jwks_uri must be a string")
		}
		set, err := r.fetchSignedJWKS(ctx, location, chain)
		if err != nil {
			return jose.JSONWebKeySet{}, err
		}
		return signingKeys(set)
	}
	if raw, present := metadata["jwks_uri"]; present {
		location, ok := raw.(string)
		if !ok {
			return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "jwks_uri must be a string")
		}
		set, err := r.fetchJWKS(ctx, location)
		if err != nil {
			return jose.JSONWebKeySet{}, err
		}
		return signingKeys(set)
	}
	return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "the %s metadata publishes no jwks, signed_jwks_uri or jwks_uri", VerifierEntityType)
}

// metadataJWKS reads a JWK Set passed by value. A key this library cannot
// parse is left out; only the public part of a key is kept.
func metadataJWKS(raw any, label string) (jose.JSONWebKeySet, error) {
	object, ok := asObject(raw)
	keys, isArray := asArray(object["keys"])
	if !ok || !isArray {
		return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "%s must be a JWK Set", label)
	}
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(keys))}
	for _, entry := range keys {
		encoded, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON(encoded); err != nil || !key.Valid() {
			continue
		}
		public := key.Public()
		if !public.Valid() {
			continue
		}
		set.Keys = append(set.Keys, public)
	}
	return set, nil
}

// signingKeys keeps the keys of set a Request Object may be signed with: use
// sig, or no use at all. OpenID Federation 1.0 Section 5.2.1 requires use on
// every key of a set that holds both signing and encryption keys.
func signingKeys(set jose.JSONWebKeySet) (jose.JSONWebKeySet, error) {
	kept := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(set.Keys))}
	for _, key := range set.Keys {
		if key.Use == "" || key.Use == "sig" {
			kept.Keys = append(kept.Keys, key)
		}
	}
	if len(kept.Keys) == 0 {
		return kept, failure(ErrVerifierKeysUnavailable, "the %s metadata publishes no signing key", VerifierEntityType)
	}
	return kept, nil
}

// fetchSignedJWKS retrieves and verifies a signed JWK Set (OpenID Federation
// 1.0 Section 5.2.1): an https URL answered with application/jwk-set+jwt, a
// JWT typed jwk-set+jwt, naming its key in kid and signed with a Federation
// Entity Key of the Verifier, whose sub is the Verifier and which is inside
// its exp.
func (r *Resolver) fetchSignedJWKS(ctx context.Context, location string, chain *TrustChain) (jose.JSONWebKeySet, error) {
	body, err := r.fetchKeyMaterial(ctx, location, "signed_jwks_uri", signedJWKSMediaType, signedJWKSMediaType)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	token := strings.TrimSpace(string(body))
	signed, err := jose.ParseSigned(token, commonJOSE.AcceptedSignatureAlgorithms())
	if err != nil || len(signed.Signatures) != 1 {
		return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "signed JWK Set is not a JWS")
	}
	header := signed.Signatures[0].Protected
	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); typ != signedJWKSTyp {
		return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "signed JWK Set typ must be %s", signedJWKSTyp)
	}
	if header.KeyID == "" {
		return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "signed JWK Set kid is required")
	}
	var payload []byte
	for _, key := range chain.Statements[0].JWKS.Key(header.KeyID) {
		if key.Algorithm != "" && key.Algorithm != header.Algorithm {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if verified, err := commonJOSE.VerifySignature(signed, key); err == nil {
			payload = verified
			break
		}
	}
	if payload == nil {
		return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "signed JWK Set is not signed with a Federation Entity Key of the verifier")
	}
	claims, err := decodeJSONObject(payload)
	if err != nil {
		return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "signed JWK Set payload is not a JSON object")
	}
	if issuer, _ := claims["iss"].(string); issuer == "" {
		return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "signed JWK Set iss is required")
	}
	if subject, _ := claims["sub"].(string); subject != chain.SubjectEntityID {
		return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "signed JWK Set sub must be the verifier's Entity Identifier")
	}
	if raw, present := claims["exp"]; present {
		expiry, ok := jsonInteger(raw)
		if !ok || !r.now().Before(time.Unix(expiry, 0)) {
			return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "signed JWK Set is expired")
		}
	}
	return metadataJWKS(map[string]any{"keys": claims["keys"]}, "signed JWK Set")
}

// fetchJWKS retrieves a JWK Set document from jwks_uri (OpenID Federation 1.0
// Section 5.2.1): an https URL answered with a JSON JWK Set.
func (r *Resolver) fetchJWKS(ctx context.Context, location string) (jose.JSONWebKeySet, error) {
	body, err := r.fetchKeyMaterial(ctx, location, "jwks_uri", "application/json", "application/json", jwkSetMediaType)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	document, err := decodeJSONObject(body)
	if err != nil {
		return jose.JSONWebKeySet{}, failure(ErrVerifierKeysUnavailable, "jwks_uri did not return a JSON object")
	}
	return metadataJWKS(document, "jwks_uri document")
}

// fetchKeyMaterial GETs a key document under the Resolver's network policy:
// https only, the public-network host policy, no redirect, a success status,
// one of the accepted media types and a bounded body.
func (r *Resolver) fetchKeyMaterial(ctx context.Context, location, label, accept string, mediaTypes ...string) ([]byte, error) {
	parsed, err := parseHTTPSFederationURL(location, label)
	if err != nil {
		return nil, failure(ErrVerifierKeysUnavailable, "%s must be an https URL", label)
	}
	if err := r.checkPublicNetworkHost(parsed.Hostname()); err != nil {
		return nil, failure(ErrVerifierKeysUnavailable, "%s must use a public network host", label)
	}
	request, err := http.NewRequestWithContext(observe.WithEndpoint(ctx, observe.EndpointJWKS), http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, failure(ErrVerifierKeysUnavailable, "%s request could not be built", label)
	}
	request.Header.Set("Accept", accept)
	response, err := r.client().Do(request)
	if err != nil {
		return nil, failure(ErrVerifierKeysUnavailable, "%s request failed", label)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, failure(ErrVerifierKeysUnavailable, "%s returned HTTP %d", label, response.StatusCode)
	}
	if !httpfetch.MediaTypeIs(response.Header, mediaTypes...) {
		return nil, failure(ErrVerifierKeysUnavailable, "%s response must use %s", label, strings.Join(mediaTypes, " or "))
	}
	body, err := httpfetch.ReadLimited(response, r.maxStatementBytes())
	if errors.Is(err, httpfetch.ErrBodyTooLarge) {
		return nil, failure(ErrVerifierKeysUnavailable, "%s response is too large", label)
	}
	if err != nil {
		return nil, failure(ErrVerifierKeysUnavailable, "%s response could not be read", label)
	}
	return body, nil
}
