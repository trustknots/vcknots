package oid4vp

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// The association of a request_uri with its Client Identifier (OpenID4VP
// 1.0 "Establishing Trust in the Request URI") needs a policy the production
// wallet can set; RequestURISameHost links the hosts the Client Identifier
// names and accepts the prefixes that name none.
func TestRequestURISameHost(t *testing.T) {
	for _, tc := range []struct {
		clientID, requestURI string
		accepted             bool
	}{
		{"x509_san_dns:verifier.example", "https://verifier.example/request/1", true},
		{"x509_san_dns:verifier.example", "https://VERIFIER.example:8443/request/1", true},
		{"x509_san_dns:verifier.example", "https://attacker.example/request/1", false},
		{"x509_san_dns:verifier.example", "http://verifier.example/request/1", false},
		{"redirect_uri:https://verifier.example/cb", "https://verifier.example/request", true},
		{"redirect_uri:https://verifier.example/cb", "https://other.example/request", false},
		{"openid_federation:https://fed.verifier.example", "https://fed.verifier.example/ro", true},
		{"https://fed.verifier.example", "https://other.example/ro", false},
		{"x509_hash:abc", "https://anywhere.example/ro", true},
		{"verifier_attestation:verifier.example", "https://anywhere.example/ro", true},
		{"registered-client", "https://anywhere.example/ro", true},
		{"", "https://anywhere.example/ro", true},
		{"x509_hash:abc", "not a url", false},
	} {
		err := RequestURISameHost(tc.clientID, tc.requestURI)
		require.Equal(t, tc.accepted, err == nil, "%s %s: %v", tc.clientID, tc.requestURI, err)
	}
}

// Set as the presenter's RequestURIPolicy, it refuses before the fetch with
// ErrRequestURINotAssociated.
func TestRequestURISameHostRefusesBeforeTheFetch(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	f.publish(t, f.draft24Claims())
	options := f.options()
	options.RequestURIPolicy = RequestURISameHost
	p := &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &options}
	uri := "openid4vp://authorize?" + url.Values{"client_id": {draft24X509ClientID}, "request_uri": {f.server.URL + "/request-object"}}.Encode()
	_, err := p.ParseDraft24Request(context.Background(), uri)
	require.ErrorIs(t, err, ErrRequestURINotAssociated)
}
