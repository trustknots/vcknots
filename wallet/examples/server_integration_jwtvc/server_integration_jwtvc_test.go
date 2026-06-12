package main

import (
	"strings"
	"testing"
)

func TestParseRunOptions_AcceptsTxCode(t *testing.T) {
	opts, err := parseRunOptions([]string{"--tx-code", "123456"})
	if err != nil {
		t.Fatalf("parseRunOptions returned error: %v", err)
	}

	if opts.TxCode != "123456" {
		t.Fatalf("TxCode = %q, want 123456", opts.TxCode)
	}
}

func TestParseRunOptions_AcceptsTxCodeAlias(t *testing.T) {
	opts, err := parseRunOptions([]string{"--tx_code", "654321"})
	if err != nil {
		t.Fatalf("parseRunOptions returned error: %v", err)
	}

	if opts.TxCode != "654321" {
		t.Fatalf("TxCode = %q, want 654321", opts.TxCode)
	}
}

func TestParseRunOptions_AcceptsCredentialOfferURI(t *testing.T) {
	opts, err := parseRunOptions([]string{"--credential-offer-uri", "openid-credential-offer://?credential_offer=%7B%7D", "--tx-code", "123456"})
	if err != nil {
		t.Fatalf("parseRunOptions returned error: %v", err)
	}

	if opts.CredentialOfferURI != "openid-credential-offer://?credential_offer=%7B%7D" {
		t.Fatalf("CredentialOfferURI = %q", opts.CredentialOfferURI)
	}
	if opts.TxCode != "123456" {
		t.Fatalf("TxCode = %q, want 123456", opts.TxCode)
	}
}

func TestParseRunOptions_RejectsPositionalArgs(t *testing.T) {
	_, err := parseRunOptions([]string{"unexpected"})
	if err == nil {
		t.Fatal("parseRunOptions returned nil error")
	}
	if !strings.Contains(err.Error(), "unexpected positional arguments") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestServerURLFromEnv(t *testing.T) {
	t.Setenv("VCKNOTS_SERVER_URL", "http://localhost:18080/")

	if got := serverURLFromEnv(); got != "http://localhost:18080" {
		t.Fatalf("serverURLFromEnv() = %q, want http://localhost:18080", got)
	}
}
