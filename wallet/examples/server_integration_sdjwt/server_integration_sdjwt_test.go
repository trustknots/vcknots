package main

import (
	"strings"
	"testing"
)

func TestParseRunOptions_TxCodeDoesNotEnableConformanceMode(t *testing.T) {
	opts, err := parseRunOptions([]string{"--tx-code", "123456"})
	if err != nil {
		t.Fatalf("parseRunOptions returned error: %v", err)
	}

	if opts.OID4VPURI != "" {
		t.Fatalf("OID4VPURI = %q, want empty", opts.OID4VPURI)
	}
	if opts.TxCode != "123456" {
		t.Fatalf("TxCode = %q, want 123456", opts.TxCode)
	}
}

func TestParseRunOptions_AcceptsOID4VPURIAndTxCode(t *testing.T) {
	opts, err := parseRunOptions([]string{"--tx_code", "654321", "openid4vp://authorize?request_uri=https://example.com/request.jwt"})
	if err != nil {
		t.Fatalf("parseRunOptions returned error: %v", err)
	}

	if opts.OID4VPURI != "openid4vp://authorize?request_uri=https://example.com/request.jwt" {
		t.Fatalf("OID4VPURI = %q", opts.OID4VPURI)
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

func TestParseRunOptions_RejectsMultipleOID4VPURIArgs(t *testing.T) {
	_, err := parseRunOptions([]string{"openid4vp://authorize?request_uri=https://example.com/1", "openid4vp://authorize?request_uri=https://example.com/2"})
	if err == nil {
		t.Fatal("parseRunOptions returned nil error")
	}
	if !strings.Contains(err.Error(), "expected at most one OID4VP URI") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestServerURLFromEnv(t *testing.T) {
	t.Setenv("VCKNOTS_SERVER_URL", "http://localhost:18080/")

	if got := serverURLFromEnv(); got != "http://localhost:18080" {
		t.Fatalf("serverURLFromEnv() = %q, want http://localhost:18080", got)
	}
}
