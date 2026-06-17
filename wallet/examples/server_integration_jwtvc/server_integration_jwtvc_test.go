package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRunOptions_AcceptsTxCode(t *testing.T) {
	opts, err := parseRunOptions([]string{"--tx-code", "123456"})
	require.NoError(t, err)
	assert.Equal(t, "123456", opts.TxCode)
}

func TestParseRunOptions_AcceptsTxCodeAlias(t *testing.T) {
	opts, err := parseRunOptions([]string{"--tx_code", "654321"})
	require.NoError(t, err)
	assert.Equal(t, "654321", opts.TxCode)
}

func TestParseRunOptions_AcceptsCredentialOfferURI(t *testing.T) {
	opts, err := parseRunOptions([]string{"--credential-offer-uri", "openid-credential-offer://?credential_offer=%7B%7D", "--tx-code", "123456"})
	require.NoError(t, err)
	assert.Equal(t, "openid-credential-offer://?credential_offer=%7B%7D", opts.CredentialOfferURI)
	assert.Equal(t, "123456", opts.TxCode)
}

func TestParseRunOptions_RejectsPositionalArgs(t *testing.T) {
	_, err := parseRunOptions([]string{"unexpected"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected positional arguments")
}

func TestServerURLFromEnv(t *testing.T) {
	t.Setenv("VCKNOTS_SERVER_URL", "http://localhost:18080/")

	assert.Equal(t, "http://localhost:18080", serverURLFromEnv())
}
