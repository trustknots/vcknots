package acceptance

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
)

// authenticateIssuer establishes the issuer key and verifies the signature
// under it. requireX5C (HAIP SD-JWT VC) makes a validated x5c chain the only
// way: IssuerX509 is required and neither UnverifiedIssuer nor
// ResolveIssuerKeysWhenX5CUntrusted applies.
//
// An x5c header is evidence only when IssuerX509 is configured. A caller that
// resolves keys itself keeps that mechanism even when x5c is present
// (SD-JWT VC §3.5 leaves the mechanism to the ecosystem).
func (a *Acceptor) authenticateIssuer(ctx context.Context, parsed *credential.Credential, policy *Policy, header map[string]any, payload map[string]any, issuer string, now time.Time, requireX5C bool, verification *Verification) error {
	if requireX5C && policy.IssuerX509 == nil {
		return fmt.Errorf("%w: HAIP requires x5c issuer authentication (IssuerX509)", ErrIssuerKeyUnresolved)
	}
	x5cRaw, x5cPresent := header["x5c"]
	if policy.IssuerX509 == nil && !policy.resolvesIssuerKeys() {
		if policy.UnverifiedIssuer {
			// No issuer key or fingerprint is recorded, so the caller can tell
			// this outcome from an authenticated one.
			return nil
		}
		if x5cPresent {
			return fmt.Errorf("%w: x5c issuer authentication is not configured", ErrIssuerKeyUnresolved)
		}
		return fmt.Errorf("%w: issuer key resolution is not configured", ErrIssuerKeyUnresolved)
	}
	if !x5cPresent || policy.IssuerX509 == nil {
		if !policy.resolvesIssuerKeys() {
			return fmt.Errorf("%w: issuer key resolution is not configured", ErrIssuerKeyUnresolved)
		}
		keys, err := resolveIssuerKeyCandidates(policy, issuer, header, payload)
		if err != nil {
			return err
		}
		return a.verifySignature(parsed, keys, verification)
	}

	certificates, err := commonX509.DecodeX5CChain(x5cRaw)
	if err != nil {
		return err
	}
	trust := policy.IssuerX509
	if a.profile.IsHAIP() {
		// HAIP §6.1.1: "The X.509 certificate of the trust anchor MUST NOT be
		// included in the x5c JOSE header". Both anchor forms are consulted.
		containsAnchor, err := commonX509.ContainsTrustAnchor(certificates, trust.TrustAnchors, trust.RootCAs)
		if err != nil {
			return err
		}
		if containsAnchor {
			return ErrHAIPTrustAnchorInX5C
		}
	}
	result, err := commonX509.VerifySigningChainWithPolicy(ctx, certificates, commonX509.SigningChainPolicy{
		TrustAnchors:                trust.TrustAnchors,
		Roots:                       trust.RootCAs,
		KeyUsages:                   trust.CertificateKeyUsages,
		CRL:                         trust.CRL,
		AllowUnadvertisedRevocation: trust.AllowUnadvertisedRevocation,
		CurrentTime:                 now,
		HTTPClient:                  revocationHTTPClient(trust.HTTPClient),
	})
	if err != nil {
		if !requireX5C && policy.ResolveIssuerKeysWhenX5CUntrusted && policy.resolvesIssuerKeys() && errors.Is(err, commonX509.ErrNoTrustAnchor) {
			keys, resolveErr := resolveIssuerKeyCandidates(policy, issuer, header, payload)
			if resolveErr != nil {
				return fmt.Errorf("issuer certificate chain reaches no configured trust anchor, and %w", resolveErr)
			}
			return a.verifySignature(parsed, keys, verification)
		}
		return fmt.Errorf("issuer certificate chain is not trusted: %w", err)
	}
	if trust.RequireIssuerDNSBinding {
		if err := requireIssuerDNSBinding(certificates[0], issuer); err != nil {
			return err
		}
	}
	verification.CertificateSHA256 = result.Fingerprints
	verification.RevocationChecked = result.Revocation.CheckedCertificates
	verification.RevocationUnadvertised = result.Revocation.NoMechanismCertificates
	if len(result.Fingerprints) > 0 {
		verification.IssuerKeyID = result.Fingerprints[0]
	}
	return a.verifySignature(parsed, []jose.JSONWebKey{{Key: certificates[0].PublicKey}}, verification)
}

// resolvesIssuerKeys reports whether the policy carries a resolver.
func (p *Policy) resolvesIssuerKeys() bool {
	return p.ResolveIssuerKeys != nil || p.ResolveIssuerKeysFromClaims != nil
}

// resolveIssuerKeyCandidates calls the policy's resolver, drops keys whose use
// or alg rules them out for this signature (RFC 7517 §4.2, §4.4), and puts the
// keys named by the header kid first. The kid orders but does not filter: the
// header is unauthenticated, and a rotated key may keep a stale kid.
func resolveIssuerKeyCandidates(policy *Policy, issuer string, header map[string]any, claims map[string]any) ([]jose.JSONWebKey, error) {
	var keys []jose.JSONWebKey
	var err error
	if policy.ResolveIssuerKeysFromClaims != nil {
		keys, err = policy.ResolveIssuerKeysFromClaims(issuer, header, claims)
	} else {
		keys, err = policy.ResolveIssuerKeys(issuer, header)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: issuer key resolution failed: %w", ErrIssuerKeyUnresolved, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no issuer key could be resolved", ErrIssuerKeyUnresolved)
	}
	algorithm, _ := header["alg"].(string)
	keys = slices.DeleteFunc(slices.Clone(keys), func(key jose.JSONWebKey) bool {
		return (key.Use != "" && key.Use != "sig") || (key.Algorithm != "" && key.Algorithm != algorithm)
	})
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no resolved issuer key is usable for signature algorithm %q", ErrIssuerKeyUnresolved, algorithm)
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		return keys, nil
	}
	ordered := make([]jose.JSONWebKey, 0, len(keys))
	for _, key := range keys {
		if key.KeyID == kid {
			ordered = append(ordered, key)
		}
	}
	for _, key := range keys {
		if key.KeyID != kid {
			ordered = append(ordered, key)
		}
	}
	return ordered, nil
}

// verifySignature verifies the issuer signature under the first candidate
// that verifies it and records that key.
func (a *Acceptor) verifySignature(parsed *credential.Credential, candidates []jose.JSONWebKey, verification *Verification) error {
	for i := range candidates {
		ok, err := a.verifier.Verify(parsed.Proof, &candidates[i])
		if err != nil || !ok {
			continue
		}
		if verification.IssuerKeyID == "" {
			verification.IssuerKeyID = candidates[i].KeyID
		}
		verified := candidates[i].Public()
		verification.IssuerKey = &verified
		return nil
	}
	return ErrIssuerSignatureInvalid
}

// requireIssuerDNSBinding binds an https iss to an exact dNSName SAN of the
// leaf (no wildcard: a wildcard authenticates a TLS server, not an issuer). A
// non-https iss names no host and is left to the rest of the policy.
func requireIssuerDNSBinding(leaf *x509.Certificate, issuer string) error {
	parsed, err := url.Parse(issuer)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return nil
	}
	host := parsed.Hostname()
	if err := commonX509.RequireLeafDNSName(leaf, host, false); err != nil {
		return fmt.Errorf("%w: issuer certificate is not bound to issuer host %q", ErrIssuerDNSBindingFailed, host)
	}
	return nil
}

// revocationHTTPClient returns client, or a bounded httpfetch client. A client
// set on IssuerX509TrustOptions.CRL takes precedence inside
// commonX509.VerifySigningChainWithPolicy.
func revocationHTTPClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return httpfetch.NewClient()
}
