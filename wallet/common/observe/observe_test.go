package observe

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func observed(t *testing.T, base http.RoundTripper, request *http.Request) (Exchange, *http.Response, error) {
	t.Helper()
	var exchanges []Exchange
	response, err := Transport(base, ObserverFunc(func(e Exchange) { exchanges = append(exchanges, e) })).RoundTrip(request)
	if len(exchanges) != 1 {
		t.Fatalf("observed %d exchanges, want 1", len(exchanges))
	}
	return exchanges[0], response, err
}

func TestTransportReportsTheExchange(t *testing.T) {
	ctx := WithEndpoint(context.Background(), EndpointCredential)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://issuer.example/credential", nil)
	if err != nil {
		t.Fatal(err)
	}
	sent := &http.Response{StatusCode: http.StatusAccepted, Body: http.NoBody}
	base := roundTripFunc(func(*http.Request) (*http.Response, error) { return sent, nil })

	exchange, response, err := observed(t, base, request)
	if err != nil || response != sent {
		t.Fatalf("round trip changed: %v %v", response, err)
	}
	if exchange.Endpoint != EndpointCredential || exchange.Request != request || exchange.Response != sent || exchange.Err != nil {
		t.Fatalf("exchange = %+v", exchange)
	}
	if exchange.StartedAt.IsZero() || exchange.Duration < 0 {
		t.Fatalf("timing = %v %v", exchange.StartedAt, exchange.Duration)
	}
}

func TestTransportReportsAFailedRoundTrip(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://issuer.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("dial failed")
	exchange, response, err := observed(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, failure
	}), request)
	if !errors.Is(err, failure) || response != nil {
		t.Fatalf("round trip changed: %v %v", response, err)
	}
	if exchange.Endpoint != EndpointOther || exchange.Response != nil || !errors.Is(exchange.Err, failure) {
		t.Fatalf("exchange = %+v", exchange)
	}
}

func TestTransportWithoutObserverIsBase(t *testing.T) {
	base := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	if got := Transport(base, nil); got == nil {
		t.Fatal("Transport(base, nil) = nil")
	}
	if Transport(nil, nil) != http.DefaultTransport {
		t.Fatal("a nil base must fall back to http.DefaultTransport")
	}
}

func TestLabels(t *testing.T) {
	if EndpointOf(context.Background()) != EndpointOther {
		t.Fatal("an unlabelled context is EndpointOther")
	}
	outer := WithEndpoint(context.Background(), EndpointCredential)
	if EndpointOf(WithEndpoint(outer, EndpointNonce)) != EndpointNonce {
		t.Fatal("an inner label replaces the outer one")
	}
	copied := WithEndpoint(context.Background(), EndpointOf(outer))
	if EndpointOf(copied) != EndpointCredential {
		t.Fatal("a label copies onto another context")
	}
}

// credentialRequest is a token request carrying every credential Transport
// redacts.
func credentialRequest(t *testing.T) *http.Request {
	t.Helper()
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {"pre-auth-secret"},
		"tx_code":             {"1234"},
		"code":                {"code-secret"},
		"code_verifier":       {"verifier-secret"},
		"client_assertion":    {"assertion-secret"},
		"refresh_token":       {"refresh-secret"},
		"client_id":           {"client-1"},
	}
	request, err := http.NewRequest(http.MethodPost, "https://as.example/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", "DPoP access-secret")
	request.Header.Set("DPoP", "dpop-secret")
	request.Header.Set("OAuth-Client-Attestation", "attestation-secret")
	request.Header.Set("OAuth-Client-Attestation-PoP", "pop-secret")
	request.Header.Set("Accept", "application/json")
	return request
}

func observedBody(t *testing.T, request *http.Request) string {
	t.Helper()
	if request.GetBody == nil {
		return ""
	}
	body, err := request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Transport hands the observer the request with its credentials replaced:
// the headers that carry a token, proof or attestation, and the form
// parameters that carry a grant or a client assertion. What is sent is
// unchanged.
func TestTransportRedactsCredentials(t *testing.T) {
	request := credentialRequest(t)
	var sentBody string
	var sentHeader http.Header
	base := roundTripFunc(func(sent *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(sent.Body)
		sentBody, sentHeader = string(raw), sent.Header.Clone()
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	exchange, _, err := observed(t, base, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"pre-auth-secret", "1234", "code-secret", "verifier-secret", "assertion-secret", "refresh-secret"} {
		if !strings.Contains(sentBody, url.QueryEscape(secret)) {
			t.Fatalf("the sent body lost %q: %s", secret, sentBody)
		}
	}
	if sentHeader.Get("Authorization") != "DPoP access-secret" || sentHeader.Get("DPoP") != "dpop-secret" {
		t.Fatalf("the sent headers changed: %v", sentHeader)
	}

	seen := exchange.Request
	if seen == request {
		t.Fatal("the observer got the original request")
	}
	if got := seen.Header.Get("Authorization"); got != "DPoP "+Redacted {
		t.Fatalf("Authorization = %q", got)
	}
	for _, name := range []string{"DPoP", "OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP"} {
		if got := seen.Header.Get(name); got != Redacted {
			t.Fatalf("%s = %q", name, got)
		}
	}
	if seen.Header.Get("Accept") != "application/json" {
		t.Fatal("a header without a credential was changed")
	}
	body := observedBody(t, seen)
	form, err := url.ParseQuery(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pre-authorized_code", "tx_code", "code", "code_verifier", "client_assertion", "refresh_token"} {
		if form.Get(name) != Redacted {
			t.Fatalf("%s = %q", name, form.Get(name))
		}
	}
	if form.Get("client_id") != "client-1" || form.Get("grant_type") == "" {
		t.Fatalf("a parameter without a credential was changed: %s", body)
	}
	if request.Header.Get("DPoP") != "dpop-secret" {
		t.Fatal("redaction changed the caller's request")
	}
}

// UnredactedTransport is the opt-in that shows the credentials.
func TestUnredactedTransportShowsCredentials(t *testing.T) {
	request := credentialRequest(t)
	var exchanges []Exchange
	base := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	if _, err := UnredactedTransport(base, ObserverFunc(func(e Exchange) { exchanges = append(exchanges, e) })).RoundTrip(request); err != nil {
		t.Fatal(err)
	}
	if len(exchanges) != 1 || exchanges[0].Request != request {
		t.Fatalf("exchanges = %+v", exchanges)
	}
	if !strings.Contains(observedBody(t, exchanges[0].Request), "pre-auth-secret") {
		t.Fatal("the unredacted body lost its credential")
	}
}
