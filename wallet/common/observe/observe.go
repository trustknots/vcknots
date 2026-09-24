// Package observe lets an integrator watch the outbound HTTP exchanges the
// wallet library performs, each labelled with the protocol role it was sent
// for.
//
// The library labels every request it builds on the request context with
// WithEndpoint. An integrator wraps the transport of the *http.Client it
// injects into the library with Transport and receives one Exchange per round
// trip, so it never re-derives a request's role from its URL.
package observe

import (
	"context"
	"net/http"
	"time"
)

// Endpoint is the protocol role of one outbound request. A request the library
// did not label (a CRL or OCSP download, a request an integrator sends through
// the same client) is EndpointOther.
type Endpoint string

const (
	// EndpointCredentialOffer is the credential_offer_uri fetch (OpenID4VCI
	// 1.0 Section 4.1.3).
	EndpointCredentialOffer Endpoint = "credential_offer"
	// EndpointIssuerMetadata is the Credential Issuer Metadata request
	// (OpenID4VCI 1.0 Section 12.2.2, Draft 13 Section 11.2.2).
	EndpointIssuerMetadata Endpoint = "issuer_metadata"
	// EndpointAuthorizationServerMetadata is the RFC 8414 metadata request.
	EndpointAuthorizationServerMetadata Endpoint = "authorization_server_metadata"
	// EndpointAuthorization is the Authorization Endpoint request the wallet
	// follows itself (OpenID4VCI 1.0 Section 5.1).
	EndpointAuthorization Endpoint = "authorization"
	// EndpointAttestationChallenge is the OAuth Client Attestation challenge
	// request.
	EndpointAttestationChallenge Endpoint = "attestation_challenge"
	// EndpointPushedAuthorization is the RFC 9126 Pushed Authorization Request.
	EndpointPushedAuthorization Endpoint = "pushed_authorization"
	// EndpointToken is the Token Request (OpenID4VCI 1.0 Section 6).
	EndpointToken Endpoint = "token"
	// EndpointNonce is the Nonce Request (OpenID4VCI 1.0 Section 7).
	EndpointNonce Endpoint = "nonce"
	// EndpointCredential is the Credential Request (OpenID4VCI 1.0 Section 8).
	EndpointCredential Endpoint = "credential"
	// EndpointDeferredCredential is the Deferred Credential Request
	// (OpenID4VCI 1.0 Section 9).
	EndpointDeferredCredential Endpoint = "deferred_credential"
	// EndpointNotification is the Notification Request (OpenID4VCI 1.0
	// Section 11).
	EndpointNotification Endpoint = "notification"
	// EndpointJWKS is a JWK Set fetch.
	EndpointJWKS Endpoint = "jwks"
	// EndpointRequestObject is the request_uri fetch of an Authorization
	// Request (OpenID4VP 1.0 Section 5.10, RFC 9101).
	EndpointRequestObject Endpoint = "request_object"
	// EndpointResponse is the Authorization Response or error response POST to
	// the verifier's Response Endpoint (OpenID4VP 1.0 Section 8.2).
	EndpointResponse Endpoint = "response_endpoint"
	// EndpointFederationEntityConfiguration is an OpenID Federation Entity
	// Configuration fetch at /.well-known/openid-federation (OpenID
	// Federation 1.0 Section 9).
	EndpointFederationEntityConfiguration Endpoint = "federation_entity_configuration"
	// EndpointFederationSubordinateStatement is a Subordinate Statement fetch
	// from a superior's federation_fetch_endpoint (OpenID Federation 1.0
	// Section 8.1).
	EndpointFederationSubordinateStatement Endpoint = "federation_subordinate_statement"
	// EndpointStatusList is a Status List Token fetch
	// (draft-ietf-oauth-status-list Section 8).
	EndpointStatusList Endpoint = "status_list"
	// EndpointIssuerKeyMaterial is a fetch the credential issuer key ladder
	// makes: JWT VC Issuer Metadata and the jwks_uri it names, a did:web DID
	// document, or a DID Configuration.
	EndpointIssuerKeyMaterial Endpoint = "issuer_key_material"
	// EndpointOther is every request the library did not label.
	EndpointOther Endpoint = "other"
)

type endpointKey struct{}

// WithEndpoint labels the requests built from ctx with their protocol role. An
// inner label replaces an outer one, so a Nonce Request issued while a
// Credential Request is being prepared is labelled EndpointNonce.
func WithEndpoint(ctx context.Context, endpoint Endpoint) context.Context {
	return context.WithValue(ctx, endpointKey{}, endpoint)
}

// EndpointOf reports the role ctx was labelled with, or EndpointOther.
func EndpointOf(ctx context.Context) Endpoint {
	if endpoint, ok := ctx.Value(endpointKey{}).(Endpoint); ok && endpoint != "" {
		return endpoint
	}
	return EndpointOther
}

// Exchange is one outbound round trip.
type Exchange struct {
	// Endpoint is the label of the request context.
	Endpoint Endpoint
	// Request is the request as handed to the transport.
	Request *http.Request
	// Response is the response, nil when Err is set. Its Body belongs to the
	// caller of the round trip.
	Response *http.Response
	// Err is the transport error.
	Err error
	// StartedAt is when the request was handed to the transport; Duration runs
	// to the response headers, so a large body streams after it.
	StartedAt time.Time
	Duration  time.Duration
}

// Observer receives the exchanges of the transport it was given to. It is
// called on the goroutine that sent the request, after the response headers
// arrived or the transport failed, so an implementation shared between
// concurrent requests must be safe for concurrent use. It must not block, read
// or close either body, or modify the request or response.
type Observer interface {
	ObserveExchange(Exchange)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(Exchange)

// ObserveExchange calls f.
func (f ObserverFunc) ObserveExchange(exchange Exchange) { f(exchange) }

// Transport returns a RoundTripper that sends through base
// (http.DefaultTransport when nil) and reports every round trip to observer. A
// nil observer returns base unchanged. Observation never changes the result of
// the round trip.
func Transport(base http.RoundTripper, observer Observer) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if observer == nil {
		return base
	}
	return &observingTransport{base: base, observer: observer}
}

type observingTransport struct {
	base     http.RoundTripper
	observer Observer
}

func (t *observingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	startedAt := time.Now()
	response, err := t.base.RoundTrip(request)
	t.observer.ObserveExchange(Exchange{
		Endpoint:  EndpointOf(request.Context()),
		Request:   request,
		Response:  response,
		Err:       err,
		StartedAt: startedAt,
		Duration:  time.Since(startedAt),
	})
	return response, err
}
