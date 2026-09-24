package jwtproof

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/trustknots/vcknots/wallet/keystore"
)

// DefaultLifetime is the validity of an assertion, PoP or attestation built
// with a zero Lifetime.
const DefaultLifetime = 5 * time.Minute

// JWT "typ" values of the tokens this package builds.
const (
	TypeDPoP                 = "dpop+jwt"
	TypeKeyProof             = "openid4vci-proof+jwt"
	TypeClientAttestation    = "oauth-client-attestation+jwt"
	TypeClientAttestationPoP = "oauth-client-attestation-pop+jwt"
	TypeKeyAttestation       = "key-attestation+jwt"
	TypeClientAssertion      = "JWT"
)

// DPoPOptions are the request facts an RFC 9449 Section 4.2 DPoP proof binds.
type DPoPOptions struct {
	// Method is the HTTP method (htm); it is upper-cased.
	Method string
	// URL is the request URL; htu is this URL without query and fragment.
	URL string
	// AccessToken, when set, is hashed into the ath claim.
	AccessToken string
	// Nonce, when set, is the server-provided DPoP nonce (Section 8).
	Nonce string
}

// DPoP builds a DPoP proof carrying key's public JWK in its header.
func DPoP(ctx context.Context, key keystore.KeyEntry, opts DPoPOptions) (string, error) {
	if strings.TrimSpace(opts.Method) == "" {
		return "", errors.New("DPoP proof requires an HTTP method")
	}
	htu, err := dpopHTU(opts.URL)
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"jti": uuid.NewString(),
		"htm": strings.ToUpper(opts.Method),
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	if opts.AccessToken != "" {
		ath := sha256.Sum256([]byte(opts.AccessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(ath[:])
	}
	if opts.Nonce != "" {
		claims["nonce"] = opts.Nonce
	}
	token, err := signWithJWK(ctx, key, "", TypeDPoP, nil, claims)
	if err != nil {
		return "", fmt.Errorf("failed to create DPoP proof: %w", err)
	}
	return token, nil
}

// dpopHTU removes the query and fragment RFC 9449 Section 4.2 excludes from htu.
func dpopHTU(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid DPoP htu URL: %w", err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", fmt.Errorf("DPoP htu URL %q is not absolute", rawURL)
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String(), nil
}

// KeyProofOptions are the inputs of an OpenID4VCI "jwt" key proof (1.0
// Appendix F.1, Draft 13 Section 7.2.1.1).
type KeyProofOptions struct {
	// Audience is the Credential Issuer Identifier (aud). Required.
	Audience string
	// Issuer is the client_id (iss); omitted when empty.
	Issuer string
	// Nonce is the c_nonce; omitted when empty.
	Nonce string
	// KeyID, when set, binds the proof by a "kid" header (for example a DID
	// URL) instead of the public JWK in a "jwk" header.
	KeyID string
	// KeyAttestation is a key attestation JWT for the key_attestation header;
	// omitted when empty.
	KeyAttestation string
	// SigningAlgValues is proof_signing_alg_values_supported; the key's
	// algorithm must be listed. Empty means no constraint.
	SigningAlgValues []jose.SignatureAlgorithm
}

// KeyProof builds a key proof of possession of key.
func KeyProof(ctx context.Context, key keystore.KeyEntry, opts KeyProofOptions) (string, error) {
	if strings.TrimSpace(opts.Audience) == "" {
		return "", errors.New("key proof requires an audience")
	}
	alg, err := SelectAlgorithm(key, opts.SigningAlgValues)
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"aud": opts.Audience,
		"iat": time.Now().Unix(),
	}
	if opts.Issuer != "" {
		claims["iss"] = opts.Issuer
	}
	if opts.Nonce != "" {
		claims["nonce"] = opts.Nonce
	}
	header := map[string]any{}
	if opts.KeyAttestation != "" {
		header["key_attestation"] = opts.KeyAttestation
	}
	var token string
	if opts.KeyID != "" {
		header["typ"] = TypeKeyProof
		header["kid"] = opts.KeyID
		token, err = Sign(ctx, key, alg, header, claims)
	} else {
		token, err = signWithJWK(ctx, key, alg, TypeKeyProof, header, claims)
	}
	if err != nil {
		return "", fmt.Errorf("failed to create key proof: %w", err)
	}
	return token, nil
}

// ClientAttestationPoPOptions are the inputs of the Client Attestation PoP JWT
// of draft-ietf-oauth-attestation-based-client-auth.
type ClientAttestationPoPOptions struct {
	// ClientID is the iss claim. Required.
	ClientID string
	// Audience is the authorization server issuer identifier. Required.
	Audience string
	// Challenge is the server-provided attestation challenge; omitted when
	// empty.
	Challenge string
	// Lifetime bounds exp; zero means DefaultLifetime.
	Lifetime time.Duration
}

// ClientAttestationPoP builds the PoP JWT signed with the wallet instance key
// the Client Attestation's cnf names.
func ClientAttestationPoP(ctx context.Context, key keystore.KeyEntry, opts ClientAttestationPoPOptions) (string, error) {
	if strings.TrimSpace(opts.ClientID) == "" {
		return "", errors.New("client attestation PoP requires a client_id")
	}
	if strings.TrimSpace(opts.Audience) == "" {
		return "", errors.New("client attestation PoP requires an audience")
	}
	now := time.Now()
	claims := map[string]any{
		"iss": opts.ClientID,
		"aud": opts.Audience,
		"jti": uuid.NewString(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(lifetime(opts.Lifetime)).Unix(),
	}
	if opts.Challenge != "" {
		claims["challenge"] = opts.Challenge
	}
	token, err := Sign(ctx, key, "", map[string]any{"typ": TypeClientAttestationPoP}, claims)
	if err != nil {
		return "", fmt.Errorf("failed to create client attestation PoP: %w", err)
	}
	return token, nil
}

// ClientAssertionOptions are the inputs of an RFC 7523 Section 2.2
// private_key_jwt client assertion.
type ClientAssertionOptions struct {
	// ClientID is both iss and sub. Required.
	ClientID string
	// Audience is the authorization server identifier. Required.
	Audience string
	// Algorithm overrides Algorithm(key); it must be one the key can produce.
	Algorithm jose.SignatureAlgorithm
	// Lifetime bounds exp; zero means DefaultLifetime.
	Lifetime time.Duration
}

// ClientAssertion builds a client assertion. The header carries the key's kid
// when it has one.
func ClientAssertion(ctx context.Context, key keystore.KeyEntry, opts ClientAssertionOptions) (string, error) {
	if key == nil {
		return "", errors.New("client assertion requires a key")
	}
	if strings.TrimSpace(opts.ClientID) == "" {
		return "", errors.New("client assertion requires a client_id")
	}
	if strings.TrimSpace(opts.Audience) == "" {
		return "", errors.New("client assertion requires an audience")
	}
	now := time.Now()
	claims := map[string]any{
		"iss": opts.ClientID,
		"sub": opts.ClientID,
		"aud": opts.Audience,
		"jti": uuid.NewString(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(lifetime(opts.Lifetime)).Unix(),
	}
	token, err := Sign(ctx, key, opts.Algorithm, withKeyID(key, map[string]any{"typ": TypeClientAssertion}), claims)
	if err != nil {
		return "", fmt.Errorf("failed to create client assertion: %w", err)
	}
	return token, nil
}

// ClientAttestationOptions are the inputs of a self-issued Client Attestation
// JWT (draft-ietf-oauth-attestation-based-client-auth Section 5.1).
type ClientAttestationOptions struct {
	// Issuer is the attester identifier (iss). Required.
	Issuer string
	// ClientID is the sub claim. Required.
	ClientID string
	// ClientKey is the wallet instance key published in cnf.jwk; only its
	// public half is used. Required.
	ClientKey jose.JSONWebKey
	// Audience, when set, restricts the attestation to one authorization
	// server (HAIP Section 4.4.1).
	Audience string
	// Chain is the attester certificate chain for the x5c header, leaf first.
	Chain []*x509.Certificate
	// Lifetime bounds exp; zero means DefaultLifetime.
	Lifetime time.Duration
}

// ClientAttestation builds a Client Attestation signed with the attester key.
func ClientAttestation(ctx context.Context, attesterKey keystore.KeyEntry, opts ClientAttestationOptions) (string, error) {
	if strings.TrimSpace(opts.Issuer) == "" {
		return "", errors.New("client attestation requires an issuer")
	}
	if strings.TrimSpace(opts.ClientID) == "" {
		return "", errors.New("client attestation requires a client_id")
	}
	clientKey, err := PublicJWK(opts.ClientKey, "")
	if err != nil {
		return "", fmt.Errorf("client attestation client key: %w", err)
	}
	now := time.Now()
	claims := map[string]any{
		"iss": opts.Issuer,
		"sub": opts.ClientID,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(lifetime(opts.Lifetime)).Unix(),
		"cnf": map[string]any{"jwk": clientKey},
	}
	if opts.Audience != "" {
		claims["aud"] = opts.Audience
	}
	token, err := Sign(ctx, attesterKey, "", attesterHeader(attesterKey, TypeClientAttestation, opts.Chain), claims)
	if err != nil {
		return "", fmt.Errorf("failed to create client attestation: %w", err)
	}
	return token, nil
}

// KeyAttestationOptions are the inputs of a self-issued key attestation
// (OpenID4VCI 1.0 Appendix D.1).
type KeyAttestationOptions struct {
	// Issuer is the attester identifier (iss). Required.
	Issuer string
	// AttestedKeys are the holder keys listed in attested_keys; only their
	// public halves are used. At least one is required.
	AttestedKeys []jose.JSONWebKey
	// Nonce is the c_nonce; omitted when empty.
	Nonce string
	// Chain is the attester certificate chain for the x5c header, leaf first.
	Chain []*x509.Certificate
	// Lifetime bounds exp; zero means DefaultLifetime.
	Lifetime time.Duration
}

// KeyAttestation builds a key attestation signed with the attester key.
func KeyAttestation(ctx context.Context, attesterKey keystore.KeyEntry, opts KeyAttestationOptions) (string, error) {
	if strings.TrimSpace(opts.Issuer) == "" {
		return "", errors.New("key attestation requires an issuer")
	}
	if len(opts.AttestedKeys) == 0 {
		return "", errors.New("key attestation requires at least one attested key")
	}
	attested := make([]jose.JSONWebKey, 0, len(opts.AttestedKeys))
	for index, key := range opts.AttestedKeys {
		public, err := PublicJWK(key, "")
		if err != nil {
			return "", fmt.Errorf("attested key %d: %w", index, err)
		}
		attested = append(attested, public)
	}
	now := time.Now()
	claims := map[string]any{
		"iss":           opts.Issuer,
		"iat":           now.Unix(),
		"exp":           now.Add(lifetime(opts.Lifetime)).Unix(),
		"attested_keys": attested,
	}
	if opts.Nonce != "" {
		claims["nonce"] = opts.Nonce
	}
	token, err := Sign(ctx, attesterKey, "", attesterHeader(attesterKey, TypeKeyAttestation, opts.Chain), claims)
	if err != nil {
		return "", fmt.Errorf("failed to create key attestation: %w", err)
	}
	return token, nil
}

// signWithJWK signs with key's public JWK in the "jwk" header, as DPoP proofs
// and jwk-bound key proofs require. No "kid" header is set.
func signWithJWK(ctx context.Context, key keystore.KeyEntry, alg jose.SignatureAlgorithm, typ string, header map[string]any, claims map[string]any) (string, error) {
	if key == nil {
		return "", errors.New("signing key is required")
	}
	if alg == "" {
		var err error
		if alg, err = Algorithm(key); err != nil {
			return "", err
		}
	}
	public, err := PublicJWK(key.PublicKey(), alg)
	if err != nil {
		return "", err
	}
	merged := map[string]any{"typ": typ, "jwk": public}
	for name, value := range header {
		merged[name] = value
	}
	return Sign(ctx, key, alg, merged, claims)
}

func attesterHeader(key keystore.KeyEntry, typ string, chain []*x509.Certificate) map[string]any {
	header := map[string]any{"typ": typ}
	if len(chain) > 0 {
		x5c := make([]string, 0, len(chain))
		for _, certificate := range chain {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(certificate.Raw))
		}
		header["x5c"] = x5c
	}
	if key == nil {
		return header
	}
	return withKeyID(key, header)
}

func withKeyID(key keystore.KeyEntry, header map[string]any) map[string]any {
	if kid := key.PublicKey().KeyID; kid != "" {
		header["kid"] = kid
	}
	return header
}

func lifetime(value time.Duration) time.Duration {
	if value <= 0 {
		return DefaultLifetime
	}
	return value
}
