package observe

import (
	"context"
	"errors"
	"net/http"
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
