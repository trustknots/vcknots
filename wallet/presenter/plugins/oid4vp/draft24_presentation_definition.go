package oid4vp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
)

// Draft 24 §6 error codes for a Presentation Definition passed by reference.
const (
	// InvalidPresentationDefinitionURIError: "The Presentation Definition
	// URL cannot be reached."
	InvalidPresentationDefinitionURIError OAuthAuthzError = "invalid_presentation_definition_uri"
	// InvalidPresentationDefinitionReferenceError: "The Presentation
	// Definition URL can be reached, but the specified
	// presentation_definition cannot be found at the URL."
	InvalidPresentationDefinitionReferenceError OAuthAuthzError = "invalid_presentation_definition_reference"
)

// maxPresentationDefinitionBytes bounds a fetched Presentation Definition.
const maxPresentationDefinitionBytes = 1 << 20

// resolvedDefinition is a Presentation Definition fetched from a
// presentation_definition_uri: the URI and the definition exactly as it was
// served.
type resolvedDefinition struct {
	uri  string
	body string
}

// setPresentationDefinition records data, the JSON of a Presentation
// Definition, as the request's definition.
func (r *CredentialPresentationRequest) setPresentationDefinition(data []byte) error {
	var definition PresentationDefinition
	if err := json.Unmarshal(data, &definition); err != nil {
		return err
	}
	r.PresentationDefinition = &definition
	// PresentationDefinition keeps only the id; the wire value is kept for a
	// caller that renders or forwards the whole definition.
	r.RawPresentationDefinition = json.RawMessage(bytes.Clone(data))
	return nil
}

// resolvePresentationDefinitionURI dereferences the presentation_definition_uri
// of an authenticated Draft 24 request (Draft 24 §5.5): "The Wallet MUST send
// an HTTP GET request without additional parameters", and "The protocol for
// the presentation_definition_uri MUST be HTTPS". A re-admission uses the
// definition its seal recorded for the same URI instead of fetching it again,
// so the Holder's consent and the presentation read one definition. The
// resolved definition becomes PresentationDefinition and
// RawPresentationDefinition; PresentationDefinitionURI keeps the reference.
func (b *draft24RequestBuilder) resolvePresentationDefinitionURI() error {
	uri := b.req.PresentationDefinitionURI
	if uri == "" {
		return nil
	}
	var body []byte
	switch {
	case b.sealedDefinition != nil:
		if b.sealedDefinition.uri != uri {
			return fmt.Errorf("%w: the sealed Presentation Definition was resolved from another presentation_definition_uri", ErrSealedAdmissionInvalid)
		}
		body = []byte(b.sealedDefinition.body)
	default:
		fetched, err := b.fetchPresentationDefinition(uri)
		if err != nil {
			return err
		}
		body = fetched
	}
	if err := b.req.setPresentationDefinition(body); err != nil || b.req.PresentationDefinition.ID == "" {
		return newAuthorizationRequestError(InvalidPresentationDefinitionReferenceError, "presentation_definition_uri does not serve a Presentation Definition")
	}
	b.resolvedDefinition = &resolvedDefinition{uri: uri, body: string(body)}
	if len(b.req.TransactionData) > 0 {
		// The input descriptors transaction_data names are known now.
		return b.validateTransactionData()
	}
	return nil
}

// fetchPresentationDefinition performs the Draft 24 §5.5 GET: https only
// (unless HTTP is allowed for local tests), no redirects, a bounded JSON body.
func (b *draft24RequestBuilder) fetchPresentationDefinition(uri string) ([]byte, error) {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Host == "" {
		return nil, newAuthorizationRequestError(InvalidPresentationDefinitionURIError, "presentation_definition_uri is not an absolute URL")
	}
	if !strings.EqualFold(parsed.Scheme, "https") && (!strings.EqualFold(parsed.Scheme, "http") || !b.allowHTTP) {
		return nil, newAuthorizationRequestError(InvalidPresentationDefinitionURIError, "presentation_definition_uri must use https")
	}
	ctx := observe.WithEndpoint(b.context(), observe.EndpointPresentationDefinition)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, newAuthorizationRequestError(InvalidPresentationDefinitionURIError, "presentation_definition_uri: %v", err)
	}
	request.Header.Set("Accept", "application/json")
	client := b.httpClient
	if client == nil {
		client = (&Oid4vpPresenter{}).httpClient()
	}
	response, err := httpfetch.NoRedirect(client).Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("%w: %w", newAuthorizationRequestError(InvalidPresentationDefinitionURIError, "presentation_definition_uri cannot be reached"), err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, newAuthorizationRequestError(InvalidPresentationDefinitionReferenceError, "presentation_definition_uri answered HTTP %d", response.StatusCode)
	}
	body, err := httpfetch.ReadLimited(response, maxPresentationDefinitionBytes)
	if err != nil {
		return nil, newAuthorizationRequestError(InvalidPresentationDefinitionReferenceError, "presentation_definition_uri: %v", err)
	}
	// RFC 8259 §8.1: JSON exchanged between systems is UTF-8; a body that is
	// not would not survive the seal byte for byte.
	if !utf8.Valid(body) || !json.Valid(body) || !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		return nil, newAuthorizationRequestError(InvalidPresentationDefinitionReferenceError, "presentation_definition_uri does not serve a JSON object")
	}
	return body, nil
}
