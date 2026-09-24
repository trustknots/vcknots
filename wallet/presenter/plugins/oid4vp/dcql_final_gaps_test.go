package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Gap 1: OID4VP 1.0 Section 6.1.1 / HAIP 1.0 section 5 aki trusted_authorities.
func TestAuthorityKeyIdentifiersFromCredential(t *testing.T) {
	authorityKeyID := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: "issuer"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		SubjectKeyId:   authorityKeyID,
		AuthorityKeyId: authorityKeyID,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	header, err := json.Marshal(map[string]any{
		"alg": "ES256",
		"x5c": []string{base64.StdEncoding.EncodeToString(der)},
	})
	require.NoError(t, err)
	wire := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("signature"))

	identifiers := AuthorityKeyIdentifiersFromCredential(wire)
	require.Equal(t, []string{base64.RawURLEncoding.EncodeToString(authorityKeyID)}, identifiers)

	// No x5c header means no aki values; the credential cannot match aki queries.
	noChain := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + ".e30.c2ln"
	require.Empty(t, AuthorityKeyIdentifiersFromCredential(noChain))
}

func TestParseDcqlTrustedAuthorities(t *testing.T) {
	valid := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"trusted_authorities":[{"type":"aki","values":["abc","def"]}]}]}`
	query, err := parseDcqlQuery(valid)
	require.NoError(t, err)
	require.Len(t, query.Credentials[0].TrustedAuthorities, 1)
	require.Equal(t, "aki", query.Credentials[0].TrustedAuthorities[0].Type)
	require.Equal(t, []string{"abc", "def"}, query.Credentials[0].TrustedAuthorities[0].Values)

	for _, tc := range []struct{ name, raw string }{
		{"not an array", `"trusted_authorities":{}`},
		{"empty array", `"trusted_authorities":[]`},
		{"entry not object", `"trusted_authorities":["aki"]`},
		{"missing type", `"trusted_authorities":[{"values":["a"]}]`},
		{"empty type", `"trusted_authorities":[{"type":"","values":["a"]}]`},
		{"missing values", `"trusted_authorities":[{"type":"aki"}]`},
		{"empty values", `"trusted_authorities":[{"type":"aki","values":[]}]`},
		{"non-string value", `"trusted_authorities":[{"type":"aki","values":[1]}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseDcqlQuery(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},` + tc.raw + `}]}`)
			assertAuthzErrorCode(t, err, InvalidRequestError)
		})
	}
}

func TestResolveDCQLTrustedAuthoritiesAKI(t *testing.T) {
	query := &DcqlQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt",
		TrustedAuthorities: []TrustedAuthority{{Type: "aki", Values: []string{"matching"}}},
	}}}
	matching := DCQLCredentialCandidate{ID: "bound", Format: "dc+sd-jwt", AuthorityKeyIDs: []string{"matching"}}
	nonMatching := DCQLCredentialCandidate{ID: "other", Format: "dc+sd-jwt", AuthorityKeyIDs: []string{"different"}}
	noChain := DCQLCredentialCandidate{ID: "nochain", Format: "dc+sd-jwt"}

	selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{matching})
	require.NoError(t, err)
	require.Len(t, selected, 1)
	require.Equal(t, "bound", selected[0].CandidateID)

	for _, candidate := range []DCQLCredentialCandidate{nonMatching, noChain} {
		selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{candidate})
		require.Error(t, err)
		require.Empty(t, selected)
	}

	// Section 6.1.1: a credential matches only by matching a value of one of
	// the listed types. A type this wallet cannot evaluate matches nothing, so
	// it cannot widen the query.
	unknown := &DcqlQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt",
		TrustedAuthorities: []TrustedAuthority{{Type: "etsi_tl", Values: []string{"x"}}},
	}}}
	selected, err = ResolveSatisfiableDCQLCredentials(unknown, []DCQLCredentialCandidate{nonMatching})
	require.ErrorIs(t, err, ErrDCQLSelectionUnsatisfied)
	require.Empty(t, selected)

	mixed := &DcqlQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt",
		TrustedAuthorities: []TrustedAuthority{
			{Type: "openid_federation", Values: []string{"https://federation.example"}},
			{Type: "aki", Values: []string{"matching"}},
		},
	}}}
	selected, err = ResolveSatisfiableDCQLCredentials(mixed, []DCQLCredentialCandidate{nonMatching, matching})
	require.NoError(t, err)
	require.Len(t, selected, 1)
	require.Equal(t, "bound", selected[0].CandidateID)
}

// Gap 2: OID4VP 1.0 Section 6.4.2 / Appendix B.3 holder binding.
func TestResolveDCQLHolderBindingSelection(t *testing.T) {
	bound := true
	unbound := false
	query := &DcqlQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt", Meta: map[string]any{},
	}}}
	unboundCandidate := DCQLCredentialCandidate{ID: "unbound", Format: "dc+sd-jwt", HolderBound: &unbound}
	boundCandidate := DCQLCredentialCandidate{ID: "bound", Format: "dc+sd-jwt", HolderBound: &bound}

	selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{unboundCandidate, boundCandidate})
	require.NoError(t, err)
	require.Len(t, selected, 1)
	require.Equal(t, "bound", selected[0].CandidateID)

	selected, err = ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{unboundCandidate})
	require.Error(t, err)
	require.Empty(t, selected)

	waived := false
	waivedQuery := &DcqlQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt", Meta: map[string]any{},
		RequireCryptographicHolderBinding: &waived,
	}}}
	selected, err = ResolveSatisfiableDCQLCredentials(waivedQuery, []DCQLCredentialCandidate{unboundCandidate})
	require.NoError(t, err)
	require.Len(t, selected, 1)
}

// Gap 3: OID4VP 1.0 Section 6.1 multiple / Section 8.1.
func TestResolveDCQLMultipleReturnsAllMatches(t *testing.T) {
	query := &DcqlQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt", Meta: map[string]any{},
		Claims: []DCQLClaimQuery{{Path: []any{"given_name"}}},
	}}}
	candidates := []DCQLCredentialCandidate{
		{ID: "one", Format: "dc+sd-jwt", Claims: []string{"given_name"}},
		{ID: "two", Format: "dc+sd-jwt", Claims: []string{"given_name"}},
	}
	selected, err := ResolveSatisfiableDCQLCredentials(query, candidates)
	require.NoError(t, err)
	require.Len(t, selected, 1)

	query.Credentials[0].Multiple = true
	selected, err = ResolveSatisfiableDCQLCredentials(query, candidates)
	require.NoError(t, err)
	require.Len(t, selected, 2)
	require.ElementsMatch(t, []string{"one", "two"}, []string{selected[0].CandidateID, selected[1].CandidateID})
}

// Gap 4: OID4VP 1.0 Section 7 claims path pointers.
func TestResolveDCQLNestedClaimPaths(t *testing.T) {
	candidate := DCQLCredentialCandidate{
		ID: "pid", Format: "dc+sd-jwt",
		ClaimObject: map[string]any{
			"address": map[string]any{"postal_code": "12345", "city": "Milliways"},
			"degrees": []any{
				map[string]any{"type": "BSc"},
				map[string]any{"type": "MSc"},
			},
			"nationalities": []any{"British", "Betelgeusian"},
		},
	}
	query := &DcqlQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt", Meta: map[string]any{},
		Claims: []DCQLClaimQuery{
			{Path: []any{"address", "postal_code"}},
			{Path: []any{"degrees", nil, "type"}},
			{Path: []any{"nationalities", 1}},
		},
	}}}
	selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{candidate})
	require.NoError(t, err)
	require.Len(t, selected, 1)
	require.ElementsMatch(t, []string{
		`["address","postal_code"]`,
		`["degrees",null,"type"]`,
		`["nationalities",1]`,
	}, selected[0].Claims)

	// Values apply to the selected nested element.
	valuesQuery := &DcqlQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt", Meta: map[string]any{},
		Claims: []DCQLClaimQuery{{Path: []any{"address", "postal_code"}, Values: []any{"99999"}}},
	}}}
	selected, err = ResolveSatisfiableDCQLCredentials(valuesQuery, []DCQLCredentialCandidate{candidate})
	require.Error(t, err)
	require.Empty(t, selected)

	// A path that selects no element is unsatisfied.
	missing := &DcqlQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt", Meta: map[string]any{},
		Claims: []DCQLClaimQuery{{Path: []any{"address", "missing"}}},
	}}}
	selected, err = ResolveSatisfiableDCQLCredentials(missing, []DCQLCredentialCandidate{candidate})
	require.Error(t, err)
	require.Empty(t, selected)
}

// Gap 5: OID4VP 1.0 Appendix B.3.3.1 per-object transaction_data_hashes_alg.
func TestFinalTransactionDataHashesAlgSelection(t *testing.T) {
	entry := base64.RawURLEncoding.EncodeToString([]byte(
		`{"type":"example","credential_ids":["cred"],"transaction_data_hashes_alg":["sha-384","sha-256"]}`))
	raw, err := json.Marshal([]string{entry})
	require.NoError(t, err)
	uri := finalQueryURI(url.Values{
		"client_id":                   {"redirect_uri:https://verifier.example/cb"},
		"redirect_uri":                {"https://verifier.example/cb"},
		"response_type":               {"vp_token"},
		"response_mode":               {"fragment"},
		"nonce":                       {"n"},
		"dcql_query":                  {finalDcqlParam},
		"transaction_data":            {string(raw)},
		"transaction_data_hashes_alg": {"sha-512"},
	})
	req, err := (&Oid4vpPresenter{SupportedTransactionDataTypes: []string{"example"}}).ParsePresentationRequest(uri)
	require.NoError(t, err)
	require.Equal(t, "sha-384", req.TransactionDataHashesAlg)

	// Absent member defaults to sha-256.
	entry = base64.RawURLEncoding.EncodeToString([]byte(`{"type":"example","credential_ids":["cred"]}`))
	raw, err = json.Marshal([]string{entry})
	require.NoError(t, err)
	uri = finalQueryURI(url.Values{
		"client_id":        {"redirect_uri:https://verifier.example/cb"},
		"redirect_uri":     {"https://verifier.example/cb"},
		"response_type":    {"vp_token"},
		"response_mode":    {"fragment"},
		"nonce":            {"n"},
		"dcql_query":       {finalDcqlParam},
		"transaction_data": {string(raw)},
	})
	req, err = (&Oid4vpPresenter{SupportedTransactionDataTypes: []string{"example"}}).ParsePresentationRequest(uri)
	require.NoError(t, err)
	require.Equal(t, "sha-256", req.TransactionDataHashesAlg)
}

// Gap 8: OID4VP 1.0 Section 8.2/8.5 typed invalid_request and scoped exclusivity.
func TestFinalInvalidRequestErrors(t *testing.T) {
	t.Run("missing nonce", func(t *testing.T) {
		uri := finalQueryURI(url.Values{
			"client_id":     {"redirect_uri:https://verifier.example/cb"},
			"redirect_uri":  {"https://verifier.example/cb"},
			"response_type": {"vp_token"},
			"response_mode": {"fragment"},
			"dcql_query":    {finalDcqlParam},
		})
		_, err := (&Oid4vpPresenter{}).ParsePresentationRequest(uri)
		assertAuthzErrorCode(t, err, InvalidRequestError)
	})
	t.Run("redirect_uri and response_uri are exclusive for direct_post", func(t *testing.T) {
		uri := finalQueryURI(url.Values{
			"client_id":     {"redirect_uri:https://verifier.example/cb"},
			"response_type": {"vp_token"},
			"response_mode": {"direct_post"},
			"response_uri":  {"https://verifier.example/response"},
			"redirect_uri":  {"https://verifier.example/cb"},
			"nonce":         {"n"},
			"dcql_query":    {finalDcqlParam},
		})
		_, err := (&Oid4vpPresenter{}).ParsePresentationRequest(uri)
		assertAuthzErrorCode(t, err, InvalidRequestError)
	})
	t.Run("both may coexist outside direct_post", func(t *testing.T) {
		uri := finalQueryURI(url.Values{
			"client_id":     {"redirect_uri:https://verifier.example/cb"},
			"response_type": {"vp_token"},
			"response_mode": {"fragment"},
			"response_uri":  {"https://verifier.example/response"},
			"redirect_uri":  {"https://verifier.example/cb"},
			"nonce":         {"n"},
			"dcql_query":    {finalDcqlParam},
		})
		req, err := (&Oid4vpPresenter{}).ParsePresentationRequest(uri)
		require.NoError(t, err)
		require.Equal(t, "https://verifier.example/response", req.ResponseURI)
	})
}
