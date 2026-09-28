package oid4vp

import (
	"fmt"
	"net/url"
	"strings"
)

// RequestURISameHost is a RequestObjectValidationOptions.RequestURIPolicy for
// Verifiers whose request_uri is served from the host their Client
// Identifier names (OpenID4VP 1.0, "Establishing Trust in the Request URI":
// a Wallet "SHOULD validate that the Request URI is properly associated with
// the Client Identifier"; "If the link cannot be established in those cases,
// the Wallet MUST refuse the request"). It runs before request_uri is fetched:
//
//   - x509_san_dns: the request_uri host is the DNS name;
//   - redirect_uri: the request_uri host is the Redirect URI's host;
//   - openid_federation (and a Draft 24 https Client Identifier): the
//     request_uri host is the Entity Identifier's host.
//
// The request_uri must use https. A Client Identifier that names no host -
// x509_hash, verifier_attestation, a pre-registered or decentralized
// identifier, or none - is accepted: nothing links it to a host before the
// fetch, and the fetched Request Object is refused unless it authenticates as
// that same Client Identifier. A trust framework that registers request_uri
// origins per Verifier composes its own policy instead.
func RequestURISameHost(clientID, requestURI string) error {
	uri, err := url.Parse(requestURI)
	if err != nil || uri.Host == "" {
		return fmt.Errorf("request_uri %q is not an absolute URL", requestURI)
	}
	if !strings.EqualFold(uri.Scheme, "https") {
		return fmt.Errorf("request_uri %q does not use https", requestURI)
	}
	host := ""
	trimmed := strings.TrimSpace(clientID)
	switch {
	case trimmed == "":
		return nil
	case strings.HasPrefix(trimmed, "https:"):
		// Draft 24 §5.10.4: an https Client Identifier is an Entity
		// Identifier.
		host = urlHost(trimmed)
	default:
		parsed, err := parseOID4VPClientID(trimmed)
		if err != nil {
			return err
		}
		switch parsed.prefix {
		case OID4VPClientIDPrefixX509SanDNS:
			host = parsed.original
		case OID4VPClientIDPrefixRedirectURI, OID4VPClientIDPrefixOIDFederation:
			host = urlHost(parsed.original)
		default:
			return nil
		}
	}
	if host == "" {
		return fmt.Errorf("the Client Identifier %q names no host", clientID)
	}
	if !strings.EqualFold(uri.Hostname(), host) {
		return fmt.Errorf("request_uri host %q is not the host %q the Client Identifier names", uri.Hostname(), host)
	}
	return nil
}

// urlHost returns the host name of an absolute URL, or "".
func urlHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
