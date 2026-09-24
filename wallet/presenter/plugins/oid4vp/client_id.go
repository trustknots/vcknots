package oid4vp

import (
	"fmt"
	"strings"
)

// OID4VPClientID is a parsed OpenID4VP Client Identifier: its Client
// Identifier Prefix and the identifier that follows it.
type OID4VPClientID struct {
	original string
	prefix   OID4VPClientIDPrefix
}

// OID4VPClientIDPrefix is an OpenID4VP Client Identifier Prefix.
type OID4VPClientIDPrefix string

// OpenID4VP Client Identifier Prefixes.
const (
	// OID4VPClientIDPrefixRedirectURI is the redirect_uri prefix.
	OID4VPClientIDPrefixRedirectURI OID4VPClientIDPrefix = "redirect_uri"
	// OID4VPClientIDPrefixOIDFederation is the openid_federation prefix.
	OID4VPClientIDPrefixOIDFederation OID4VPClientIDPrefix = "openid_federation"
	// OID4VPClientIDPrefixDID is parsed, but the parse entry points refuse it:
	// this library does not resolve DIDs to authenticate a Request Object.
	OID4VPClientIDPrefixDID OID4VPClientIDPrefix = "decentralized_identifier"
	// OID4VPClientIDPrefixVerifierAttestation is the verifier_attestation prefix.
	OID4VPClientIDPrefixVerifierAttestation OID4VPClientIDPrefix = "verifier_attestation"
	// OID4VPClientIDPrefixX509SanDNS is the x509_san_dns prefix.
	OID4VPClientIDPrefixX509SanDNS OID4VPClientIDPrefix = "x509_san_dns"
	// OID4VPClientIDPrefixX509Hash is the x509_hash prefix.
	OID4VPClientIDPrefixX509Hash OID4VPClientIDPrefix = "x509_hash"
	// OID4VPClientIDPrefixOriginal is the origin prefix, reserved for Digital
	// Credentials API requests; ParseOID4VPClientID refuses it.
	OID4VPClientIDPrefixOriginal OID4VPClientIDPrefix = "origin"
	// OID4VPClientIDPrefixPreRegistered is the pseudo-prefix used when the
	// client_id contains no ":" character (OID4VP 1.0 §5.9.2).
	OID4VPClientIDPrefixPreRegistered OID4VPClientIDPrefix = "pre-registered"
)

// ParseOID4VPClientID parses a client_id with the OID4VP 1.0 §5.9.2 syntax
// every entry point of this package applies. A Client Identifier with no ":"
// reports OID4VPClientIDPrefixPreRegistered. The Wallet-only prefixes "origin"
// (§5.9.3) and "web-origin" (Appendix A.2) are refused with
// ErrClientIDPrefixReserved, and unknown prefixes as a syntax error. Parsing
// a prefix does not mean the parse entry points can authenticate it.
func ParseOID4VPClientID(clientID string) (*OID4VPClientID, error) {
	return parseOID4VPClientIDAllowingWebOrigin(clientID, false)
}

// Prefix reports the Client Identifier Prefix this Client Identifier carries,
// or OID4VPClientIDPrefixPreRegistered when it carries none.
func (c *OID4VPClientID) Prefix() OID4VPClientIDPrefix {
	return c.prefix
}

// Original reports the <orig_client_id> part of the Client Identifier: the
// value after the prefix, or the whole identifier for a pre-registered client.
func (c *OID4VPClientID) Original() string {
	return c.original
}

// RequiresRequestObjectSignature reports whether the prefix itself can only be
// authenticated by a signed Request Object: x509_san_dns, x509_hash and
// verifier_attestation (OID4VP 1.0 §5.9.3). The parse entry points refuse
// such a request in plain parameters with ErrRequestObjectSignatureRequired.
func (c *OID4VPClientID) RequiresRequestObjectSignature() bool {
	return c.prefix == OID4VPClientIDPrefixX509SanDNS ||
		c.prefix == OID4VPClientIDPrefixX509Hash ||
		c.prefix == OID4VPClientIDPrefixVerifierAttestation
}

// parseOID4VPClientID is the package-internal spelling of ParseOID4VPClientID.
func parseOID4VPClientID(clientID string) (*OID4VPClientID, error) {
	return ParseOID4VPClientID(clientID)
}

// parseClientID parses a client_id for the delivery this builder processes.
// Only an unsigned DC API request accepts "web-origin:<origin>", which
// parseDCAPIUnsigned synthesised itself after discarding the request's
// client_id (OID4VP 1.0 Appendix A.2).
func (b *requestBuilder) parseClientID(clientID string) (*OID4VPClientID, error) {
	return parseOID4VPClientIDAllowingWebOrigin(clientID, b.requestSource == sourceDCAPIUnsigned)
}

// parseOID4VPClientIDAllowingWebOrigin implements the OID4VP 1.0 Section 5.9.2
// Client Identifier syntax. allowWebOrigin is true only on the one internal
// path that synthesises the identifier itself; see parseClientID.
func parseOID4VPClientIDAllowingWebOrigin(clientID string, allowWebOrigin bool) (*OID4VPClientID, error) {
	// Syntax: <client_id_prefix>:<orig_client_id>

	// Trim whitespace from client_id
	clientID = strings.TrimSpace(clientID)

	parts := strings.SplitN(clientID, ":", 2)
	if len(parts) != 2 {
		// OID4VP 1.0 §5.9.2: "If a `:` character is not present in the Client
		// Identifier, the Wallet MUST treat the Client Identifier as
		// referencing a pre-registered client."
		if clientID == "" {
			return nil, fmt.Errorf("invalid client_id format")
		}
		return &OID4VPClientID{original: clientID, prefix: OID4VPClientIDPrefixPreRegistered}, nil
	}

	prefix := parts[0]
	origin := strings.TrimSpace(parts[1])

	// Detect duplicate prefix (e.g., "x509_san_dns:x509_san_dns:...")
	if strings.HasPrefix(origin, prefix+":") {
		return nil, fmt.Errorf("invalid client_id: duplicate prefix detected")
	}

	switch OID4VPClientIDPrefix(prefix) {
	case OID4VPClientIDPrefixRedirectURI,
		OID4VPClientIDPrefixOIDFederation,
		OID4VPClientIDPrefixDID,
		OID4VPClientIDPrefixVerifierAttestation,
		OID4VPClientIDPrefixX509SanDNS,
		OID4VPClientIDPrefixX509Hash:
		return &OID4VPClientID{
			original: origin,
			prefix:   OID4VPClientIDPrefix(prefix),
		}, nil
	case OID4VPClientIDPrefixWebOrigin:
		// OID4VP 1.0 Appendix A.2: "The `client_id` parameter MUST be omitted
		// in unsigned requests defined in (#unsigned_request). The Wallet MUST
		// ignore any `client_id` parameter that is present in an unsigned
		// request." web-origin is the effective identifier the Wallet derives
		// from the platform-authenticated Origin, so accepting it from a
		// request would let a Verifier name itself and derive no response
		// endpoint binding, which is what Section 5.9.3 forbids for the
		// companion "origin" prefix.
		if !allowWebOrigin {
			return nil, fmt.Errorf("client_id prefix 'web-origin' is reserved for the Wallet's own unsigned Digital Credentials API identifier and is not allowed in requests: %w", ErrClientIDPrefixReserved)
		}
		return &OID4VPClientID{
			original: origin,
			prefix:   OID4VPClientIDPrefixWebOrigin,
		}, nil
	case OID4VPClientIDPrefixOriginal:
		// OID4VP 1.0 Section 5.9.3: "This reserved Client Identifier Prefix is
		// defined in (#dc_api_request). The Wallet MUST NOT accept this Client
		// Identifier Prefix in requests."
		return nil, fmt.Errorf("client_id prefix 'origin' is not allowed: %w", ErrClientIDPrefixReserved)
	default:
		// OID4VP 1.0 Section 5.9.2 defines the syntax as
		// "<client_id_prefix>:<orig_client_id>" over a closed set of prefixes,
		// so name the token that was parsed as the prefix rather than implying
		// the Wallet merely does not implement it yet.
		return nil, fmt.Errorf("client_id prefix %q is not a supported Client Identifier Prefix", prefix)
	}
}
