package attestation

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	commonjose "github.com/trustknots/vcknots/wallet/common/jose"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/profile"
)

// JOSEHeader is the protected header of an attestation JWT, as a KeyResolver
// sees it. It is unauthenticated.
type JOSEHeader struct {
	Type      string   // typ
	Algorithm string   // alg
	KeyID     string   // kid; empty when absent
	X5C       []string // x5c entries (base64 DER); empty when absent
}

// KeyResolver returns the public key that verifies an attestation without an
// x5c header: a Wallet Provider JWKS entry chosen by kid, or a locally known
// attester key. The result may be a crypto.PublicKey, a jose.JSONWebKey or a
// *jose.JSONWebKey. An error refuses the attestation.
type KeyResolver func(header JOSEHeader) (any, error)

// TrustPolicy says how attestation JWTs are authenticated. An attestation with
// x5c is verified with its leaf key, and the chain is validated when anchors
// are configured; one without x5c is verified with ResolveKey. There is no
// way to accept an unverified attestation.
type TrustPolicy struct {
	// X5C applies the HAIP 1.0 certificate rules of §4.4.1 and §4.5.1:
	// Require refuses an attestation without x5c, RejectSelfSigned a
	// self-signed signing certificate, and ExcludeAnchor a chain that
	// includes a configured trust anchor. The wallet adds the rules of its
	// profile's Options.AttestationX5C.
	X5C profile.X5CRules
	// TrustAnchors or RootCAs (at most one) are the Wallet Provider anchors.
	// Without them an x5c chain is not validated, only the signature is, and
	// under X5C.Require or X5C.ExcludeAnchor (HAIP) an attestation with x5c
	// is refused.
	TrustAnchors []*x509.Certificate
	RootCAs      *x509.CertPool
	// KeyUsages constrains the attester certificate's extended key usage.
	KeyUsages []x509.ExtKeyUsage
	// AllowUnadvertisedRevocation accepts certificates that advertise no
	// revocation mechanism; one that advertises only OCSP is still refused.
	AllowUnadvertisedRevocation bool
	// CRL tunes revocation retrieval. CRL.HTTPClient is required when anchors
	// are configured; CRL.RequireStatus is derived from
	// AllowUnadvertisedRevocation.
	CRL commonX509.CRLCheckerOptions
	// ResolveKey verifies attestations that carry no x5c. It is not consulted
	// for one that does.
	ResolveKey KeyResolver
	// Now is the verification clock; nil means time.Now.
	Now func() time.Time
}

func (p TrustPolicy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// ValidateClientAttestation authenticates a Wallet Attestation under policy,
// then checks typ, sub against the client_id, cnf.jwk against the client key,
// a present aud against the authorization server (HAIP §4.4.1 forbids reuse
// across Issuers; an absent aud is accepted because the Client Attestation
// JWT defines none, see ClientProvider) and exp. Failures wrap
// ErrClientAttestationInvalid.
func ValidateClientAttestation(ctx context.Context, attestation *ClientAttestation, request ClientRequest, policy TrustPolicy) error {
	if err := validateClient(ctx, attestation, request, policy); err != nil {
		return fmt.Errorf("%w: %w", ErrClientAttestationInvalid, err)
	}
	return nil
}

// ValidateKeyAttestation authenticates a key attestation under policy, then
// checks typ, exp, the nonce against a given c_nonce, a present aud against
// the audience, and that every requested key is in attested_keys. Failures
// wrap ErrKeyAttestationInvalid.
func ValidateKeyAttestation(ctx context.Context, attestation *KeyAttestation, request KeyRequest, policy TrustPolicy) error {
	if err := validateKey(ctx, attestation, request, policy); err != nil {
		return fmt.Errorf("%w: %w", ErrKeyAttestationInvalid, err)
	}
	return nil
}

func validateClient(ctx context.Context, attestation *ClientAttestation, request ClientRequest, policy TrustPolicy) error {
	if attestation == nil || strings.TrimSpace(attestation.JWT) == "" {
		return errors.New("client attestation provider returned an empty attestation")
	}
	header, _, err := parseJWT(attestation.JWT)
	if err != nil {
		return fmt.Errorf("client attestation is malformed: %w", err)
	}
	now := policy.now()
	if err := authenticate(ctx, attestation.JWT, header, policy, "client attestation", now); err != nil {
		return err
	}
	return checkClientClaims(attestation, request, now)
}

func validateKey(ctx context.Context, attestation *KeyAttestation, request KeyRequest, policy TrustPolicy) error {
	if attestation == nil || strings.TrimSpace(attestation.JWT) == "" {
		return errors.New("key attestation provider returned an empty attestation")
	}
	header, _, err := parseJWT(attestation.JWT)
	if err != nil {
		return fmt.Errorf("key attestation is malformed: %w", err)
	}
	now := policy.now()
	if err := authenticate(ctx, attestation.JWT, header, policy, "key attestation", now); err != nil {
		return err
	}
	return checkKeyClaims(attestation, request, now)
}

// checkClientClaims checks the claims of an authenticated Wallet Attestation.
func checkClientClaims(attestation *ClientAttestation, request ClientRequest, now time.Time) error {
	header, claims, err := parseJWT(attestation.JWT)
	if err != nil {
		return fmt.Errorf("client attestation is malformed: %w", err)
	}
	if header.Type != clientAttestationType {
		return fmt.Errorf("client attestation typ must be %q, got %q", clientAttestationType, header.Type)
	}
	if claims.Sub != request.ClientID {
		return fmt.Errorf("client attestation sub %q does not match client_id %q", claims.Sub, request.ClientID)
	}
	if !audienceMatches(claims.Aud, request.AuthorizationServer) {
		return fmt.Errorf("client attestation aud %v does not identify the authorization server %q", claims.Aud, request.AuthorizationServer)
	}
	if claims.Cnf == nil || claims.Cnf.JWK.Key == nil {
		return errors.New("client attestation is missing cnf.jwk")
	}
	// draft-ietf-oauth-attestation-based-client-auth Section 5.1: cnf holds
	// the key the Client Instance proves possession of, which RFC 7800
	// Section 3.2 conveys as a public key JWK. A cnf.jwk with private members
	// or a symmetric key would be forwarded unchanged to the Authorization
	// Server.
	if !claims.Cnf.JWK.IsPublic() {
		return errors.New("client attestation cnf.jwk is not a public asymmetric key")
	}
	if err := sameKey(request.ClientKey, claims.Cnf.JWK); err != nil {
		return fmt.Errorf("client attestation cnf.jwk does not match the wallet client key: %w", err)
	}
	return checkExpiry("client attestation", claims.Exp, attestation.ExpiresAt, now)
}

// checkKeyClaims checks the claims of an authenticated key attestation.
func checkKeyClaims(attestation *KeyAttestation, request KeyRequest, now time.Time) error {
	header, claims, err := parseJWT(attestation.JWT)
	if err != nil {
		return fmt.Errorf("key attestation is malformed: %w", err)
	}
	if header.Type != keyAttestationType {
		return fmt.Errorf("key attestation typ must be %q, got %q", keyAttestationType, header.Type)
	}
	if err := checkExpiry("key attestation", claims.Exp, attestation.ExpiresAt, now); err != nil {
		return err
	}
	if request.Nonce != "" && claims.Nonce != request.Nonce {
		return fmt.Errorf("key attestation nonce %q does not match the issuer c_nonce %q", claims.Nonce, request.Nonce)
	}
	if !audienceMatches(claims.Aud, request.Audience) {
		return fmt.Errorf("key attestation aud %v does not identify the credential issuer %q", claims.Aud, request.Audience)
	}
	attested := make(map[string]struct{}, len(claims.AttestedKeys))
	for index := range claims.AttestedKeys {
		// OpenID4VCI 1.0 Appendix D: attested_keys lists the cryptographic
		// public keys whose properties the attestation asserts. An entry with
		// private members or a symmetric key would be forwarded unchanged to
		// the Credential Issuer.
		if claims.AttestedKeys[index].Key != nil && !claims.AttestedKeys[index].IsPublic() {
			return fmt.Errorf("key attestation attested_keys[%d] is not a public asymmetric key", index)
		}
		sum, err := thumbprint(claims.AttestedKeys[index])
		if err != nil {
			return fmt.Errorf("key attestation attested_keys[%d] is invalid: %w", index, err)
		}
		attested[sum] = struct{}{}
	}
	for index := range request.Keys {
		sum, err := thumbprint(request.Keys[index])
		if err != nil {
			return fmt.Errorf("holder key at index %d is invalid: %w", index, err)
		}
		if _, ok := attested[sum]; !ok {
			return fmt.Errorf("key attestation does not attest the holder key at index %d", index)
		}
	}
	return nil
}

// checkExpiry requires exp and refuses the attestation at the earlier of exp
// and the provider's ExpiresAt.
func checkExpiry(label string, exp *float64, expiresAt time.Time, now time.Time) error {
	if exp == nil {
		return fmt.Errorf("%s is missing exp", label)
	}
	expiry := time.Unix(int64(*exp), 0)
	if !expiresAt.IsZero() && expiresAt.Before(expiry) {
		expiry = expiresAt
	}
	if !now.Before(expiry) {
		return fmt.Errorf("%s is expired", label)
	}
	return nil
}

type jwtHeader struct {
	Type      string   `json:"typ"`
	Algorithm string   `json:"alg"`
	KeyID     string   `json:"kid"`
	X5C       []string `json:"x5c"`
}

type jwtClaims struct {
	Iss          string            `json:"iss"`
	Sub          string            `json:"sub"`
	Aud          any               `json:"aud"`
	Exp          *float64          `json:"exp"`
	Nonce        string            `json:"nonce"`
	AttestedKeys []jose.JSONWebKey `json:"attested_keys"`
	Cnf          *struct {
		JWK jose.JSONWebKey `json:"jwk"`
	} `json:"cnf"`
}

// audienceMatches reports whether aud (a string or an array of strings)
// names audience. An absent aud makes no audience claim and matches.
func audienceMatches(aud any, audience string) bool {
	switch value := aud.(type) {
	case nil:
		return true
	case string:
		return value == audience
	case []any:
		return slices.ContainsFunc(value, func(entry any) bool {
			text, ok := entry.(string)
			return ok && text == audience
		})
	default:
		return false
	}
}

// parseJWT decodes the header and claims of a compact JWS without verifying it.
func parseJWT(token string) (jwtHeader, jwtClaims, error) {
	var header jwtHeader
	var claims jwtClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return header, claims, errors.New("expected a compact JWS with three parts")
	}
	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return header, claims, fmt.Errorf("invalid protected header encoding: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return header, claims, fmt.Errorf("invalid protected header JSON: %w", err)
	}
	payloadBytes, err := decodeSegment(parts[1])
	if err != nil {
		return header, claims, fmt.Errorf("invalid payload encoding: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return header, claims, fmt.Errorf("invalid payload JSON: %w", err)
	}
	return header, claims, nil
}

// decodeSegment decodes a base64url JWS segment, tolerating padding.
func decodeSegment(segment string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(segment, "="))
}

// sameKey fails unless want and got have the same RFC 7638 thumbprint.
func sameKey(want jose.JSONWebKey, got jose.JSONWebKey) error {
	wantThumbprint, err := thumbprint(want)
	if err != nil {
		return err
	}
	gotThumbprint, err := thumbprint(got)
	if err != nil {
		return err
	}
	if wantThumbprint != gotThumbprint {
		return errors.New("thumbprint mismatch")
	}
	return nil
}

func thumbprint(key jose.JSONWebKey) (string, error) {
	if key.Key == nil {
		return "", errors.New("missing key")
	}
	public := key.Public()
	sum, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// authenticate verifies who signed the attestation before any claim is
// believed: the x5c leaf when present (with the chain validated against
// configured anchors), ResolveKey otherwise. label names the artifact in
// errors.
func authenticate(ctx context.Context, token string, header jwtHeader, policy TrustPolicy, label string, now time.Time) error {
	var chain []*x509.Certificate
	if len(header.X5C) > 0 {
		decoded, err := commonX509.DecodeX5CChain(header.X5C)
		if err != nil {
			return fmt.Errorf("%s x5c header is invalid: %w", label, err)
		}
		chain = decoded
	}
	if policy.X5C.Require && len(chain) == 0 {
		return fmt.Errorf("%s must include an x5c header chain", label)
	}
	if policy.X5C.RejectSelfSigned && len(chain) > 0 {
		if err := commonX509.RequireNonSelfSignedLeaf(chain, label); err != nil {
			return err
		}
	}
	var key any
	if len(chain) > 0 {
		if err := verifyChain(ctx, chain, policy, label, now); err != nil {
			return err
		}
		key = chain[0].PublicKey
	} else {
		if policy.ResolveKey == nil {
			return fmt.Errorf("%s cannot be authenticated: it carries no x5c chain and the attestation trust policy configures no key resolver", label)
		}
		resolved, err := policy.ResolveKey(JOSEHeader(header))
		if err != nil {
			return fmt.Errorf("%s signing key could not be resolved: %w", label, err)
		}
		if resolved == nil {
			return fmt.Errorf("%s signing key could not be resolved: the resolver returned no key", label)
		}
		key = resolved
	}
	// OpenID4VCI 1.0 Appendix D.1 (and the Wallet Attestation draft for
	// Appendix E): alg "MUST NOT be `none` or an identifier for a symmetric
	// algorithm (MAC)", which the accepted set never includes.
	signed, err := jose.ParseSigned(token, commonjose.AcceptedSignatureAlgorithms())
	if err != nil {
		return fmt.Errorf("%s is not a verifiable JWS: %w", label, err)
	}
	if len(signed.Signatures) != 1 {
		return fmt.Errorf("%s must carry exactly one signature", label)
	}
	// RFC 7518 Sections 3.3 and 3.5: an RSA key shorter than 2048 bits is
	// refused before the signature is checked under it.
	if _, err := commonjose.VerifySignature(signed, key); err != nil {
		return fmt.Errorf("%s signature could not be verified: %w", label, err)
	}
	return nil
}

// verifyChain validates an x5c chain against the configured anchors. Without
// anchors there is nothing to validate against, which only a policy without
// HAIP's certificate rules accepts: under X5C.Require or X5C.ExcludeAnchor
// (HAIP §4.4.1, §4.5.1) an unanchored chain would authenticate an
// attestation signed by any certificate, so it is refused. Under
// X5C.ExcludeAnchor the chain must not carry the anchor.
func verifyChain(ctx context.Context, chain []*x509.Certificate, policy TrustPolicy, label string, now time.Time) error {
	if len(policy.TrustAnchors) == 0 && policy.RootCAs == nil {
		if policy.X5C.Require || policy.X5C.ExcludeAnchor {
			return fmt.Errorf("%s x5c chain cannot be validated: the profile requires a trusted chain and the attestation trust policy configures no TrustAnchors or RootCAs", label)
		}
		return nil
	}
	if policy.X5C.ExcludeAnchor {
		containsAnchor, err := commonX509.ContainsTrustAnchor(chain, policy.TrustAnchors, policy.RootCAs)
		if err != nil {
			return fmt.Errorf("%s x5c header is invalid: %w", label, err)
		}
		if containsAnchor {
			return fmt.Errorf("X5CRules.ExcludeAnchor forbids including the trust anchor certificate in the x5c header of the %s", label)
		}
	}
	if policy.CRL.HTTPClient == nil {
		// A certificate must not choose where an unguarded default client goes.
		return fmt.Errorf("%s trust anchors are configured but the policy supplies no CRL HTTP client", label)
	}
	if _, err := commonX509.VerifySigningChainWithPolicy(ctx, chain, commonX509.SigningChainPolicy{
		TrustAnchors:                policy.TrustAnchors,
		Roots:                       policy.RootCAs,
		KeyUsages:                   policy.KeyUsages,
		CRL:                         policy.CRL,
		AllowUnadvertisedRevocation: policy.AllowUnadvertisedRevocation,
		CurrentTime:                 now,
	}); err != nil {
		return fmt.Errorf("%s certificate chain is not trusted: %w", label, err)
	}
	return nil
}
