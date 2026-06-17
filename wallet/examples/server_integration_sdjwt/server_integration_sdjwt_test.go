package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRunOptions_TxCodeDoesNotEnableConformanceMode(t *testing.T) {
	opts, err := parseRunOptions([]string{"--tx-code", "123456"})
	require.NoError(t, err)
	assert.Empty(t, opts.OID4VPURI)
	assert.Equal(t, "123456", opts.TxCode)
}

func TestParseRunOptions_AcceptsOID4VPURIAndTxCode(t *testing.T) {
	opts, err := parseRunOptions([]string{"--tx_code", "654321", "openid4vp://authorize?request_uri=https://example.com/request.jwt"})
	require.NoError(t, err)
	assert.Equal(t, "openid4vp://authorize?request_uri=https://example.com/request.jwt", opts.OID4VPURI)
	assert.Equal(t, "654321", opts.TxCode)
}

func TestParseRunOptions_AcceptsCredentialOfferURI(t *testing.T) {
	opts, err := parseRunOptions([]string{"--credential-offer-uri", "openid-credential-offer://?credential_offer=%7B%7D", "--tx-code", "123456"})
	require.NoError(t, err)
	assert.Equal(t, "openid-credential-offer://?credential_offer=%7B%7D", opts.CredentialOfferURI)
	assert.Equal(t, "123456", opts.TxCode)
}

func TestParseRunOptions_RejectsMultipleOID4VPURIArgs(t *testing.T) {
	_, err := parseRunOptions([]string{"openid4vp://authorize?request_uri=https://example.com/1", "openid4vp://authorize?request_uri=https://example.com/2"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected at most one OID4VP URI")
}

func TestParseRunOptions_RejectsCredentialOfferURIWithOID4VPURI(t *testing.T) {
	_, err := parseRunOptions([]string{"--credential-offer-uri", "openid-credential-offer://?credential_offer=%7B%7D", "openid4vp://authorize?request_uri=https://example.com/request.jwt"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--credential-offer-uri cannot be used with positional OID4VP URI")
}

func TestServerURLFromEnv(t *testing.T) {
	t.Setenv("VCKNOTS_SERVER_URL", "http://localhost:18080/")

	assert.Equal(t, "http://localhost:18080", serverURLFromEnv())
}
