package oid4vp

import (
	"net/url"
	"strings"
)

// bindDraft24RedirectURIResponseURI holds a Draft24 redirect_uri Client
// Identifier to the Response URI of a direct_post request, the rule the Final
// path applies in setParamsWithAnyMap. Draft24 Section 5.10.1 states it the
// same way: with the redirect_uri scheme the Client Identifier "is the Redirect
// URI (or Response URI when Response Mode direct_post is used)".
//
// One tolerance is kept for Verifiers still speaking the pre-Draft22 wire,
// which named the scheme in a separate client_id_scheme parameter and sent a
// bare https Client Identifier naming the Verifier's base URL rather than its
// callback. Such a request may name a Response URI of the same https origin
// whose path lies under the Client Identifier's path (the Client Identifier
// "https://verifier.example/" answers at "https://verifier.example/cb" only when
// its own path is not "/"). The tolerance applies only while the request still
// carries that client_id_scheme=redirect_uri parameter, never widens the
// origin, and never admits plain http.
func bindDraft24RedirectURIResponseURI(
	params map[string]any,
	clientID string,
	redirectURIFromClientID string,
	responseURI string,
	responseMode OAuthAuthzReqResponseMode,
) error {
	if redirectURIFromClientID == "" || !isDirectPostMode(responseMode) || responseURI == "" {
		return nil
	}
	if !strings.HasPrefix(clientID, string(OID4VPClientIDPrefixRedirectURI)+":") {
		return nil
	}
	if responseURI == redirectURIFromClientID {
		return nil
	}
	if legacyScheme, _ := params["client_id_scheme"].(string); legacyScheme == string(OID4VPClientIDPrefixRedirectURI) &&
		legacyRedirectURIResponseURIAllowed(redirectURIFromClientID, responseURI) {
		return nil
	}
	return newAuthorizationRequestError(InvalidRequestError, "%w", ErrResponseURIClientIDMismatch)
}

// legacyRedirectURIResponseURIAllowed reports whether responseURI is a
// callback of the pre-Draft22 Verifier whose base URL is clientURI: the same
// https origin, and either the same path or a path under a non-root client
// path.
func legacyRedirectURIResponseURIAllowed(clientURI string, responseURI string) bool {
	client, err := url.Parse(clientURI)
	if err != nil {
		return false
	}
	response, err := url.Parse(responseURI)
	if err != nil {
		return false
	}
	if client.Scheme != "https" || response.Scheme != "https" || client.Host != response.Host {
		return false
	}
	clientPath := client.EscapedPath()
	responsePath := response.EscapedPath()
	if clientPath == "" {
		clientPath = "/"
	}
	if responsePath == clientPath {
		return true
	}
	if clientPath == "/" {
		return false
	}
	base := clientPath
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return strings.HasPrefix(responsePath, base)
}
