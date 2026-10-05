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
// reports OID4VPClientIDPrefixPreRegistered. The reserved prefix "origin"
// (§5.9.3) is refused with ErrClientIDPrefixReserved, and unknown prefixes as
// a syntax error. Parsing a prefix does not mean the parse entry points can
// authenticate it.
func ParseOID4VPClientID(clientID string) (*OID4VPClientID, error) {
	return parseOID4VPClientID(clientID)
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
// verifier_attestation (OID4VP 1.0 §5.9.3), and openid_federation, whose
// Relying Party "MUST demonstrate that the requesting Entity controls the
// Entity's RP keys" by signing the request (OpenID Federation 1.0 §12.1.1).
// The parse entry points refuse such a request in plain parameters with
// ErrRequestObjectSignatureRequired.
func (c *OID4VPClientID) RequiresRequestObjectSignature() bool {
	return c.prefix == OID4VPClientIDPrefixX509SanDNS ||
		c.prefix == OID4VPClientIDPrefixX509Hash ||
		c.prefix == OID4VPClientIDPrefixVerifierAttestation ||
		c.prefix == OID4VPClientIDPrefixOIDFederation
}

// parseClientID parses a client_id with the OpenID4VP 1.0 syntax.
func (b *requestBuilder) parseClientID(clientID string) (*OID4VPClientID, error) {
	return parseOID4VPClientID(clientID)
}

// parseOID4VPClientID implements the OID4VP 1.0 Section 5.9.2 Client
// Identifier syntax.
func parseOID4VPClientID(clientID string) (*OID4VPClientID, error) {
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
