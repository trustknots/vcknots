package oid4vp

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// The helpers below return the admitted request itself, for tests that
// inspect what a parse produced.

func admittedRequest(handle types.AdmittedRequest, err error) (*CredentialPresentationRequest, error) {
	if err != nil {
		return nil, err
	}
	return handle.(*AdmittedRequest).req, nil
}

func parseDraft24ForTest(p *Oid4vpPresenter, uri string) (*CredentialPresentationRequest, error) {
	return admittedRequest(p.ParseDraft24Request(context.Background(), uri))
}

func parseRequestObjectForTest(p *Oid4vpPresenter, requestObject, clientID string) (*CredentialPresentationRequest, error) {
	return admittedRequest(p.ParseRequestObject(context.Background(), requestObject, types.RequestObjectSource{ClientID: clientID}))
}

func parseDraft24RequestObjectForTest(p *Oid4vpPresenter, requestObject, clientID string) (*CredentialPresentationRequest, error) {
	return admittedRequest(p.ParseDraft24RequestObject(context.Background(), requestObject, types.RequestObjectSource{ClientID: clientID}))
}

func parseDCAPIForTest(p *Oid4vpPresenter, invocation types.DCAPIInvocation) (*CredentialPresentationRequest, error) {
	return admittedRequest(p.ParseDCAPIRequest(context.Background(), invocation))
}

func parseRequestObjectWithSourceForTest(p *Oid4vpPresenter, requestObject string, src types.RequestObjectSource) (*CredentialPresentationRequest, error) {
	return admittedRequest(p.ParseRequestObject(context.Background(), requestObject, src))
}

// admitDirectPost admits an unsigned direct_post request whose redirect_uri
// Client Identifier names responseURI.
func admitDirectPost(t *testing.T, p *Oid4vpPresenter, responseURI, state string) types.AdmittedRequest {
	t.Helper()
	values := url.Values{
		"client_id":     {"redirect_uri:" + responseURI},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"n"},
		"dcql_query":    {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}`},
	}
	if state != "" {
		values.Set("state", state)
	}
	handle, err := p.ParseRequest(context.Background(), "openid4vp://authorize?"+values.Encode())
	if err != nil {
		t.Fatalf("admit direct_post request: %v", err)
	}
	return handle
}

// encryptResponseForTest encrypts an authorization response the way a
// direct_post.jwt submission does.
func encryptResponseForTest(p *Oid4vpPresenter, response map[string]any, metadata *VerifierMetadata) (string, error) {
	payload, err := json.Marshal(response)
	if err != nil {
		return "", err
	}
	return p.encryptAuthorizationResponseJWE(payload, metadata)
}
