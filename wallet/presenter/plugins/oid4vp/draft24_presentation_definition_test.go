package oid4vp

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustknots/vcknots/wallet/profile"
)

// definitionServer serves a Presentation Definition at /pd and counts the
// fetches; body is read under the lock, so a test can change it.
type definitionServer struct {
	*httptest.Server
	mu      sync.Mutex
	body    string
	status  int
	fetches atomic.Int32
	methods []string
	queries []string
}

func newDefinitionServer(t *testing.T, body string) *definitionServer {
	s := &definitionServer{body: body, status: http.StatusOK}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.fetches.Add(1)
		s.mu.Lock()
		s.methods = append(s.methods, r.Method)
		s.queries = append(s.queries, r.URL.RawQuery)
		body, status := s.body, s.status
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *definitionServer) set(body string, status int) {
	s.mu.Lock()
	s.body, s.status = body, status
	s.mu.Unlock()
}

const servedDefinition = `{"id":"pd-by-reference","input_descriptors":[{"id":"pid","format":{"vc+sd-jwt":{}}}]}`

func draft24DefinitionURIQuery(definitionURI string) url.Values {
	return url.Values{
		"client_id":                   {"redirect_uri:https://verifier.example/response"},
		"response_type":               {"vp_token"},
		"response_mode":               {"direct_post"},
		"nonce":                       {"n"},
		"presentation_definition_uri": {definitionURI},
	}
}

// Draft 24 §5.5: "The Wallet MUST send an HTTP GET request without additional
// parameters." The library resolves the reference while admitting the
// request, so consent and presentation read the definition it fetched.
func TestDraft24ResolvesPresentationDefinitionURI(t *testing.T) {
	server := newDefinitionServer(t, servedDefinition)
	p := &Oid4vpPresenter{HTTPClient: server.Client()}
	definitionURI := server.URL + "/pd?ref=idcard"
	request, err := parseDraft24ForTest(p, "openid4vp://present?"+draft24DefinitionURIQuery(definitionURI).Encode())
	require.NoError(t, err)
	require.Equal(t, definitionURI, request.PresentationDefinitionURI)
	require.Equal(t, "pd-by-reference", request.PresentationDefinition.ID)
	require.JSONEq(t, servedDefinition, string(request.RawPresentationDefinition))
	require.Equal(t, []string{http.MethodGet}, server.methods)
	require.Equal(t, []string{"ref=idcard"}, server.queries, "no additional parameters")
}

// Draft 24 §6 names the errors of a reference that fails, and §5.5 requires
// HTTPS.
func TestDraft24PresentationDefinitionURIFailures(t *testing.T) {
	server := newDefinitionServer(t, servedDefinition)
	p := &Oid4vpPresenter{HTTPClient: server.Client()}
	parse := func(uri string) error {
		_, err := parseDraft24ForTest(p, "openid4vp://present?"+draft24DefinitionURIQuery(uri).Encode())
		return err
	}
	assertAuthzErrorCode(t, parse("http://verifier.example/pd"), InvalidPresentationDefinitionURIError)
	server.set(`{"error":"gone"}`, http.StatusNotFound)
	assertAuthzErrorCode(t, parse(server.URL+"/pd"), InvalidPresentationDefinitionReferenceError)
	server.set(`not json`, http.StatusOK)
	assertAuthzErrorCode(t, parse(server.URL+"/pd"), InvalidPresentationDefinitionReferenceError)
	server.set(`{"input_descriptors":[]}`, http.StatusOK)
	assertAuthzErrorCode(t, parse(server.URL+"/pd"), InvalidPresentationDefinitionReferenceError)
	server.Close()
	assertAuthzErrorCode(t, parse(server.URL+"/pd"), InvalidPresentationDefinitionURIError)
}

// Draft 24 §6 (invalid_request): "The request contains more than one out of
// the following three options".
func TestDraft24RefusesDefinitionByValueAndByReference(t *testing.T) {
	params := draft24DefinitionURIQuery("https://verifier.example/pd")
	params.Set("presentation_definition", servedDefinition)
	_, err := parseDraft24ForTest(&Oid4vpPresenter{}, "openid4vp://present?"+params.Encode())
	assertAuthzErrorCode(t, err, InvalidRequestError)
}

// transaction_data names input descriptors (Draft 24 §5.1), which a definition
// passed by reference supplies only once it is resolved.
func TestDraft24TransactionDataIsCheckedAgainstTheResolvedDefinition(t *testing.T) {
	server := newDefinitionServer(t, servedDefinition)
	p := &Oid4vpPresenter{HTTPClient: server.Client(), SupportedTransactionDataTypes: []string{"example"}}
	parse := func(credentialID string) error {
		params := draft24DefinitionURIQuery(server.URL + "/pd")
		entry := base64.RawURLEncoding.EncodeToString([]byte(`{"type":"example","credential_ids":["` + credentialID + `"]}`))
		params.Set("transaction_data", `["`+entry+`"]`)
		_, err := parseDraft24ForTest(p, "openid4vp://present?"+params.Encode())
		return err
	}
	require.NoError(t, parse("pid"))
	assertAuthzErrorCode(t, parse("unknown"), InvalidTransactionDataError)
}

// A signed Request Object carrying presentation_definition_uri stays answerable
// after consent, although the re-admission from the seal sees only the URI. The
// seal records the definition fetched for the authenticated URI, and the
// re-admission reads it without fetching again, even when the Verifier now
// serves another definition.
func TestSealedDraft24AdmissionCarriesTheResolvedDefinition(t *testing.T) {
	server := newDefinitionServer(t, servedDefinition)
	f := newRequestObjectFixture(t, "verifier.example")
	claims := f.draft24Claims()
	delete(claims, "presentation_definition")
	claims["presentation_definition_uri"] = server.URL + "/pd"
	f.publish(t, claims)
	p := f.sealedPresenter(profile.Final(), f.now)

	admitted, err := p.ParseDraft24Request(context.Background(), f.referenceURI(draft24X509ClientID, false))
	require.NoError(t, err)
	handle := admitted.(*AdmittedRequest)
	require.Equal(t, "pd-by-reference", handle.Request().PresentationDefinition.ID)
	sealed, err := handle.Seal(sealKey)
	require.NoError(t, err)
	require.EqualValues(t, 1, server.fetches.Load())

	server.set(`{"id":"changed","input_descriptors":[]}`, http.StatusOK)
	readmitted, err := p.ReadmitDraft24Request(context.Background(), sealed, sealKey)
	require.NoError(t, err)
	request := readmitted.(*AdmittedRequest).Request()
	require.Equal(t, "pd-by-reference", request.PresentationDefinition.ID)
	require.JSONEq(t, servedDefinition, string(request.RawPresentationDefinition))
	require.EqualValues(t, 1, server.fetches.Load(), "the re-admission does not fetch the definition again")

	// A seal whose recorded definition belongs to another URI than the
	// re-authenticated Request Object names is refused.
	record := decodeSealedRecord(t, strings.Split(string(sealed), ".")[1])
	record.PresentationDefinitionURI = server.URL + "/other"
	_, err = p.ReadmitDraft24Request(context.Background(), resealRecord(t, record), sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionInvalid)
}
