package oid4vci

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
)

// FetchCredentialOffer dereferences a credential_offer_uri (OpenID4VCI 1.0
// Section 4.1.3) with this receiver's HTTP client and scheme policy and
// returns the Credential Offer Object. Section 4.1.3 requires the response to
// use the media type application/json. ctx bounds the request.
func (o *Oid4vciReceiver) FetchCredentialOffer(ctx context.Context, uri common.URIField) ([]byte, error) {
	response, err := o.do(observe.WithEndpoint(ctx, observe.EndpointCredentialOffer), exchange{method: http.MethodGet, url: url.URL(uri)})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credential_offer_uri: %w", err)
	}
	if response.statusCode != http.StatusOK {
		return nil, fmt.Errorf("credential_offer_uri request failed: %w", response.statusError())
	}
	if !httpfetch.MediaTypeIs(response.header, "application/json") {
		return nil, fmt.Errorf("credential_offer_uri response has media type %q, want application/json", httpfetch.MediaType(response.header))
	}
	if len(bytes.TrimSpace(response.body)) == 0 {
		return nil, fmt.Errorf("credential_offer_uri response body is empty")
	}
	return response.body, nil
}

// HTTPAllowed reports whether this receiver accepts plain http endpoints
// (AllowHTTP), so a caller can apply the same policy to identifiers it checks
// itself.
func (o *Oid4vciReceiver) HTTPAllowed() bool {
	return o.AllowHTTP
}
