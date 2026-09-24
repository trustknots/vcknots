package x509

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
)

// maxX5CCertificates bounds a JOSE x5c chain. It is the bound
// VerifySigningCertificateChain already enforces, so a chain accepted by this
// decoder is never rejected for its length further along the trust path.
const maxX5CCertificates = 16

// ErrX5CInvalid classifies every malformed x5c header this package rejects, so
// a caller can tell a decoding failure from an authentication failure with
// errors.Is instead of matching error text.
var ErrX5CInvalid = common.NewCodedError("x5c_invalid", "x5c header is invalid")

// DecodeX5CChain decodes a JOSE x5c header value into its certificate chain,
// leaf first. raw is the value as it appears in a decoded JOSE header: either
// a []string read into a typed header, or the []any of strings encoding/json
// produces for a map[string]any header.
//
// Each entry is "a base64-encoded (Section 4 of [RFC4648] -- not
// base64url-encoded) DER [ITU.X690.2008] PKIX certificate value"
// (RFC 7515 Section 4.1.6). base64url input is reported as invalid rather than
// repaired, because a wallet that repairs it accepts chains no conforming
// verifier would. The chain must hold between 1 and 16 certificates.
//
// Decoding is not authentication: the returned chain is still untrusted input
// until VerifySigningCertificateChain accepts it against configured anchors.
func DecodeX5CChain(raw any) ([]*x509.Certificate, error) {
	encoded, err := x5cHeaderEntries(raw)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maxX5CCertificates {
		return nil, fmt.Errorf("x5c header must contain between 1 and %d certificates: %w", maxX5CCertificates, ErrX5CInvalid)
	}
	chain := make([]*x509.Certificate, 0, len(encoded))
	for index, entry := range encoded {
		der, err := base64.StdEncoding.DecodeString(entry)
		if err != nil {
			return nil, fmt.Errorf("x5c certificate %d is not valid base64 DER: %w: %w", index, err, ErrX5CInvalid)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("x5c certificate %d is not valid base64 DER: %w: %w", index, err, ErrX5CInvalid)
		}
		chain = append(chain, certificate)
	}
	return chain, nil
}

// DecodeX5CFromJWTHeader decodes the x5c chain carried by the protected header
// of a compact JWS or JWT. Only the header is read; obj's signature is not
// verified here, because the key that would verify it is the leaf this call
// returns. The header member is decoded by DecodeX5CChain and inherits its
// encoding and length rules.
func DecodeX5CFromJWTHeader(obj string) ([]*x509.Certificate, error) {
	parts := strings.Split(obj, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("x5c source is not a compact JWS: %w", ErrX5CInvalid)
	}
	// Trim padding a non-conforming producer may have added: the protected
	// header is base64url without padding (RFC 7515 Section 2).
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "="))
	if err != nil {
		return nil, fmt.Errorf("JWS protected header is not valid base64url: %w: %w", err, ErrX5CInvalid)
	}
	header := map[string]any{}
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, fmt.Errorf("JWS protected header is not valid JSON: %w: %w", err, ErrX5CInvalid)
	}
	value, present := header["x5c"]
	if !present {
		return nil, fmt.Errorf("x5c header is required: %w", ErrX5CInvalid)
	}
	return DecodeX5CChain(value)
}

// isSelfSigned reports whether cert is self-issued and carries its own
// signature. Subject and issuer are compared as raw DER rather than as their
// string rendering, and the signature is verified with the certificate's own
// public key: a certificate that merely repeats a subject DN in its issuer
// field, as a re-keyed CA of the same name does, is not self-signed.
func isSelfSigned(cert *x509.Certificate) bool {
	if cert == nil || len(cert.Raw) == 0 || !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// RequireNonSelfSignedLeaf enforces "The X.509 certificate signing the request
// MUST NOT be self-signed" (HAIP Sections 5 and 6.1.1) on a decoded chain.
// label names the signed artifact in the error, for example "wallet
// attestation" or "key attestation".
func RequireNonSelfSignedLeaf(chain []*x509.Certificate, label string) error {
	if len(chain) == 0 {
		return fmt.Errorf("%s must include an x5c header chain", label)
	}
	if chain[0] == nil || len(chain[0].Raw) == 0 {
		return fmt.Errorf("%s x5c leaf certificate is empty", label)
	}
	if isSelfSigned(chain[0]) {
		return fmt.Errorf("%s x5c leaf certificate must not be self-signed", label)
	}
	return nil
}

// x5cHeaderEntries normalises the two shapes an x5c member reaches this
// package in without copying the string values.
func x5cHeaderEntries(raw any) ([]string, error) {
	switch value := raw.(type) {
	case []string:
		return value, nil
	case []any:
		entries := make([]string, 0, len(value))
		for index, item := range value {
			entry, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("x5c certificate %d is not a string: %w", index, ErrX5CInvalid)
			}
			entries = append(entries, entry)
		}
		return entries, nil
	case nil:
		return nil, fmt.Errorf("x5c header is required: %w", ErrX5CInvalid)
	default:
		return nil, fmt.Errorf("x5c header must be an array of base64-encoded certificates: %w", ErrX5CInvalid)
	}
}

// LeafThumbprintB64u returns the OpenID4VP 1.0 Section 5.9.3 x509_hash value of
// a leaf certificate: "the base64url-encoded value of the SHA-256 hash of the
// DER-encoded X.509 certificate". An empty certificate yields the empty string,
// which never equals a well-formed identifier.
func LeafThumbprintB64u(leaf *x509.Certificate) string {
	if leaf == nil || len(leaf.Raw) == 0 {
		return ""
	}
	digest := sha256.Sum256(leaf.Raw)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// RequireLeafThumbprint enforces the OpenID4VP 1.0 Section 5.9.3 x509_hash
// binding: "the original Client Identifier (the part without the `x509_hash:`
// prefix) MUST be a hash and match the hash of the leaf certificate passed with
// the request". expectedB64u is compared byte for byte, because base64url is
// the only encoding the section defines for it.
func RequireLeafThumbprint(leaf *x509.Certificate, expectedB64u string) error {
	if leaf == nil || len(leaf.Raw) == 0 {
		return fmt.Errorf("x5c leaf certificate is empty: %w", ErrX5CInvalid)
	}
	if strings.TrimSpace(expectedB64u) == "" {
		return errors.New("x509_hash client_id is empty")
	}
	if LeafThumbprintB64u(leaf) != expectedB64u {
		return errors.New("x509_hash client_id mismatch")
	}
	return nil
}

// RequireLeafDNSName enforces that host appears as a dNSName Subject
// Alternative Name of the leaf certificate.
//
// With wildcard false the name matches exactly (case-insensitively, RFC 4343)
// and a wildcard SAN never matches, as OpenID4VP 1.0 Section 5.9.3 requires
// for x509_san_dns and OpenID4VCI 1.0 Section 12.2.2 for an issuer host; every
// caller in this library passes false. With wildcard true the RFC 6125
// Section 6.4.3 rule applies: a wildcard left-most label matches exactly one
// label.
func RequireLeafDNSName(leaf *x509.Certificate, host string, wildcard bool) error {
	if leaf == nil || len(leaf.Raw) == 0 {
		return fmt.Errorf("x5c leaf certificate is empty: %w", ErrX5CInvalid)
	}
	normalizedHost := normalizeDNSName(host)
	if normalizedHost == "" {
		return errors.New("DNS name to match is empty")
	}
	for _, name := range leaf.DNSNames {
		candidate := normalizeDNSName(name)
		if candidate == "" {
			continue
		}
		if candidate == normalizedHost {
			return nil
		}
		if wildcard && matchWildcardDNSName(candidate, normalizedHost) {
			return nil
		}
	}
	return errors.New("SAN of the certificate and client_id did not match")
}

// normalizeDNSName lowercases a DNS name and drops the trailing dot of an
// absolute name, which is the case-insensitive comparison RFC 4343 defines. No
// other normalization is applied: an internationalized name must already be in
// its A-label form, as RFC 5280 requires inside a dNSName SAN.
func normalizeDNSName(name string) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(name), ".")
	return strings.ToLower(trimmed)
}

// matchWildcardDNSName applies RFC 6125 Section 6.4.3 to an already normalized
// SAN entry and host: the wildcard is the complete left-most label of the SAN
// and covers exactly one label of the host.
func matchWildcardDNSName(san string, host string) bool {
	suffix, found := strings.CutPrefix(san, "*.")
	if !found || suffix == "" || strings.Contains(suffix, "*") {
		return false
	}
	label, rest, found := strings.Cut(host, ".")
	return found && label != "" && rest == suffix
}
