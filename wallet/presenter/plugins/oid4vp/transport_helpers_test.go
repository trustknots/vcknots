package oid4vp

import (
	"context"
	"fmt"
	"net/url"

	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// sendDCQLForTest drives the DCQL response transport directly with the
// response parameters a test names, bypassing request admission.
func sendDCQLForTest(p *Oid4vpPresenter, endpoint url.URL, vpToken map[string][]string, request *types.PresentationRequest) (string, error) {
	if request == nil {
		return "", fmt.Errorf("presentation request is required")
	}
	metadata, _ := request.ClientMetadata.(*VerifierMetadata)
	redirectURI, _, err := p.postDCQLResponse(context.Background(), endpoint.String(), vpToken, request.State, request.ResponseMode, metadata)
	return redirectURI, err
}

// sendPresentationExchangeForTest is sendDCQLForTest for a Draft 24
// Presentation Exchange response.
func sendPresentationExchangeForTest(p *Oid4vpPresenter, endpoint url.URL, vpToken []byte, submission types.PresentationSubmission, request *types.PresentationRequest) (string, error) {
	var state, mode string
	var metadata *VerifierMetadata
	if request != nil {
		state, mode = request.State, request.ResponseMode
		metadata, _ = request.ClientMetadata.(*VerifierMetadata)
	}
	redirectURI, _, err := p.postPresentationExchangeResponse(context.Background(), endpoint.String(), vpToken, submission, state, mode, metadata)
	return redirectURI, err
}
