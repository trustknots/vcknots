package oid4vp

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// TestSubmitDCQLResponseAnswersAtTheAdmittedEndpoint: the response goes to
// the endpoint and state the request was admitted with. Editing the copy
// Request returns changes neither.
func TestSubmitDCQLResponseAnswersAtTheAdmittedEndpoint(t *testing.T) {
	p, endpoint, forms, calls := dcqlTransportEndpoint(t)
	handle := admitDirectPost(t, p, endpoint.String(), "state-1")
	admitted := handle.(*AdmittedRequest)
	require.Equal(t, endpoint.String(), admitted.ResponseEndpoint().String())
	require.Empty(t, admitted.RequestObject())
	require.False(t, admitted.Draft24())

	copied := admitted.Request()
	copied.State = "forged"
	copied.ResponseURI = "https://attacker.example/response"
	copied.DcqlQuery.Credentials[0].ID = "forged"
	admitted.ResponseEndpoint().Host = "attacker.example"

	result, err := p.SubmitDCQLResponse(context.Background(), handle, map[string][]string{"pid": {"presentation"}})
	require.NoError(t, err)
	require.Equal(t, "https://verifier.example/complete", result.RedirectURI)
	require.False(t, result.Encrypted)
	form := requireDCQLForm(t, forms, calls)
	require.Equal(t, "state-1", form.Get("state"))
	require.Equal(t, "pid", admitted.Request().DcqlQuery.Credentials[0].ID)
}

// TestAdmittedRequestAnswersOnlyAtItsPresenter: another presenter instance,
// even an identically configured one, refuses the handle before sending
// anything, and so does a handle of another type.
func TestAdmittedRequestAnswersOnlyAtItsPresenter(t *testing.T) {
	p, endpoint, _, calls := dcqlTransportEndpoint(t)
	handle := admitDirectPost(t, p, endpoint.String(), "")
	other := &Oid4vpPresenter{HTTPClient: p.HTTPClient}

	_, err := other.SubmitDCQLResponse(context.Background(), handle, map[string][]string{"pid": {"presentation"}})
	require.ErrorIs(t, err, ErrRequestNotAdmittedHere)
	_, err = other.SubmitPresentationExchangeResponse(context.Background(), handle, []byte("vp"), types.PresentationSubmission{})
	require.ErrorIs(t, err, ErrRequestNotAdmittedHere)
	_, err = p.SubmitDCQLResponse(context.Background(), foreignAdmittedRequest{}, map[string][]string{"pid": {"presentation"}})
	require.ErrorIs(t, err, ErrRequestNotAdmittedHere)
	_, err = p.SubmitDCQLResponse(context.Background(), (*AdmittedRequest)(nil), map[string][]string{"pid": {"presentation"}})
	require.ErrorIs(t, err, ErrRequestNotAdmittedHere)
	require.Zero(t, calls.Load())
}

type foreignAdmittedRequest struct{}

func (foreignAdmittedRequest) Protocol() types.SupportedPresentationProtocol { return types.Oid4vp }

// TestAdmittedRequestTakesOnlyItsVersionsResponse: a DCQL response does not
// answer a Draft 24 request and a Presentation Exchange response does not
// answer an OpenID4VP 1.0 request.
func TestAdmittedRequestTakesOnlyItsVersionsResponse(t *testing.T) {
	p, endpoint, _, calls := dcqlTransportEndpoint(t)
	final := admitDirectPost(t, p, endpoint.String(), "")
	_, err := p.SubmitPresentationExchangeResponse(context.Background(), final, []byte("vp"), types.PresentationSubmission{})
	require.ErrorIs(t, err, ErrResponseTypeMismatch)

	draft, err := p.ParseDraft24Request(context.Background(), draft24DirectPostURI(endpoint))
	require.NoError(t, err)
	require.True(t, draft.(*AdmittedRequest).Draft24())
	_, err = p.SubmitDCQLResponse(context.Background(), draft, map[string][]string{"pid": {"presentation"}})
	require.ErrorIs(t, err, ErrResponseTypeMismatch)
	require.Zero(t, calls.Load())
}

// TestSubmitPresentationExchangeResponse posts vp_token and
// presentation_submission to the Draft 24 request's response_uri.
func TestSubmitPresentationExchangeResponse(t *testing.T) {
	p, endpoint, forms, calls := dcqlTransportEndpoint(t)
	draft, err := p.ParseDraft24Request(context.Background(), draft24DirectPostURI(endpoint))
	require.NoError(t, err)

	submission := types.PresentationSubmission{ID: "submission", DefinitionID: "definition", DescriptorMap: []types.DescriptorMapItem{{ID: "pid", Format: "dc+sd-jwt", Path: "$"}}}
	result, err := p.SubmitPresentationExchangeResponse(context.Background(), draft, []byte("credential~kb"), submission)
	require.NoError(t, err)
	require.Equal(t, "https://verifier.example/complete", result.RedirectURI)
	form := requireDCQLForm(t, forms, calls)
	require.Equal(t, "credential~kb", form.Get("vp_token"))
	require.Equal(t, "draft-state", form.Get("state"))
	var sent types.PresentationSubmission
	require.NoError(t, json.Unmarshal([]byte(form.Get("presentation_submission")), &sent))
	require.Equal(t, submission, sent)

	_, err = p.SubmitPresentationExchangeResponse(context.Background(), draft, nil, submission)
	require.ErrorIs(t, err, types.ErrInvalidPresentation)
}

// TestAdmittedRequestKeepsTheRequestObject: a request authenticated from a
// Request Object carries it, so a caller can parse it again later.
func TestAdmittedRequestKeepsTheRequestObject(t *testing.T) {
	f := newRequestObjectFixture(t)
	requestObject := f.sign(t, f.claims(), nil)
	p := f.presenter()
	handle, err := p.ParseRequestObject(context.Background(), requestObject, types.RequestObjectSource{ClientID: f.clientID()})
	require.NoError(t, err)
	require.Equal(t, requestObject, handle.(*AdmittedRequest).RequestObject())

	again, err := p.ParseRequestObject(context.Background(), handle.(*AdmittedRequest).RequestObject(), types.RequestObjectSource{ClientID: f.clientID()})
	require.NoError(t, err)
	require.Equal(t, handle.(*AdmittedRequest).Request().Nonce, again.(*AdmittedRequest).Request().Nonce)
}

func draft24DirectPostURI(endpoint url.URL) string {
	return "openid4vp://present?" + url.Values{
		"client_id":               {"redirect_uri:" + endpoint.String()},
		"response_type":           {"vp_token"},
		"response_mode":           {"direct_post"},
		"response_uri":            {endpoint.String()},
		"nonce":                   {"draft-nonce"},
		"state":                   {"draft-state"},
		"presentation_definition": {`{"id":"definition"}`},
	}.Encode()
}
