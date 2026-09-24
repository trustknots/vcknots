package oid4vp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// parseResponseURI parses a response_uri and enforces what OID4VP 1.0 requires
// of the Response Endpoint: an absolute URL whose scheme is https, unless http
// is explicitly allowed for testing. A relative reference or an authority-less
// URL ("https:///callback") never addresses a Verifier, so it is refused here
// rather than handed to an HTTP client that would resolve it against nothing.
//
// Every refusal wraps ErrResponseURIInvalid, so an integrator that has to tell
// a caller mistake from a Verifier or network failure branches with errors.Is
// instead of reproducing these rules ahead of the call.
func parseResponseURI(responseURI string, allowHTTP bool) (*url.URL, error) {
	if responseURI == "" {
		return nil, fmt.Errorf("%w: response_uri is required", ErrResponseURIInvalid)
	}
	parsed, err := url.Parse(responseURI)
	if err != nil {
		return nil, fmt.Errorf("%w: response_uri must be URI: %w", ErrResponseURIInvalid, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: response_uri must be an absolute URL", ErrResponseURIInvalid)
	}
	if !allowHTTP && !strings.EqualFold(parsed.Scheme, "https") {
		return nil, fmt.Errorf("%w: response_uri must use https scheme", ErrResponseURIInvalid)
	}
	return parsed, nil
}

// postAuthorizationResponse form-POSTs to the Verifier's Response Endpoint
// without following redirects: a redirect could move the response to another
// host or to plain http. The response body is read up to
// httpfetch.DefaultBodyLimit; a non-2xx status keeps only the OAuth error code,
// because the body is under the Verifier's control.
func postAuthorizationResponse(ctx context.Context, client *http.Client, endpoint string, formData url.Values) ([]byte, error) {
	ctx = observe.WithEndpoint(ctx, observe.EndpointResponse)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpfetch.NoRedirect(client).Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, readErr := httpfetch.ReadLimited(resp, httpfetch.DefaultBodyLimit)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &VerifierResponseError{
			StatusCode: resp.StatusCode,
			OAuthError: oauthErrorCodeFromResponseBody(body),
		}
	}
	if readErr != nil {
		return nil, fmt.Errorf("failed to read verifier response: %w", readErr)
	}
	return body, nil
}

// Present sends the presentation to the verifier.
// The vp_token is a JSON object keyed by the DCQL Credential Query id, as
// defined in OID4VP 1.0 Section 8.1:
// {"<credential query id>": ["<presentation>"]}
func (p *Oid4vpPresenter) Present(protocol types.SupportedPresentationProtocol, endpoint url.URL, serializedPresentation []byte, request *types.PresentationRequest) (string, error) {
	if protocol != types.Oid4vp {
		return "", fmt.Errorf("plugin type mismatch")
	}
	if request == nil || request.CredentialQueryID == "" {
		return "", fmt.Errorf("credential query id is required to build vp_token")
	}
	metadata, _ := request.ClientMetadata.(*VerifierMetadata)
	vpToken := map[string][]string{request.CredentialQueryID: {string(serializedPresentation)}}
	redirectURI, _, err := p.postDCQLResponse(context.Background(), endpoint.String(), vpToken, request.State, request.ResponseMode, metadata)
	return redirectURI, err
}

// SubmitDCQLResponse answers an admitted OpenID4VP 1.0 request with vp_token,
// keyed by DCQL credential query id (OID4VP 1.0 §8.1). An empty non-nil map is
// the Holder declining every optional query. direct_post posts the response,
// direct_post.jwt posts it encrypted (§8.3), and a DC API request gets
// SubmitResult.DCAPIResponse (Appendix A.4) with no HTTP call.
func (p *Oid4vpPresenter) SubmitDCQLResponse(ctx context.Context, req types.AdmittedRequest, vpToken map[string][]string) (*types.SubmitResult, error) {
	handle, err := p.admittedHere(req)
	if err != nil {
		return nil, err
	}
	if handle.wire != wireOpenID4VP1 {
		return nil, fmt.Errorf("%w: a DCQL response answers an OpenID4VP 1.0 request", ErrResponseTypeMismatch)
	}
	if handle.isDCAPI() {
		response, encrypted, err := p.dcapiResponse(handle.req, vpToken)
		if err != nil {
			return nil, err
		}
		return &types.SubmitResult{DCAPIResponse: response, Encrypted: encrypted}, nil
	}
	redirectURI, encrypted, err := p.postDCQLResponse(ctx, handle.endpoint.String(), vpToken, handle.req.State, string(handle.req.ResponseMode), handle.req.ClientMetadata)
	if err != nil {
		return nil, err
	}
	return &types.SubmitResult{RedirectURI: redirectURI, Encrypted: encrypted}, nil
}

// postDCQLResponse posts one Authorization Response carrying vpToken. mode is
// the request's response_mode; "" encrypts when metadata asks for it.
func (p *Oid4vpPresenter) postDCQLResponse(ctx context.Context, endpoint string, vpToken map[string][]string, state, mode string, metadata *VerifierMetadata) (string, bool, error) {
	// A nil vp_token is a caller mistake: json.Marshal would send the JSON
	// literal null, which is not the object OID4VP 1.0 §8.1 defines. An empty
	// non-nil map is the answer to a request whose optional credential_sets the
	// holder declined for every query (OID4VP 1.0 §6.4.2) and must be sent as
	// the empty object {}.
	if vpToken == nil {
		return "", false, fmt.Errorf("presentation request and vp_token are required")
	}
	for id, tokens := range vpToken {
		if id == "" || len(tokens) == 0 {
			return "", false, fmt.Errorf("vp_token query id and presentations must not be empty")
		}
		for _, token := range tokens {
			if token == "" {
				return "", false, fmt.Errorf("vp_token presentation must not be empty")
			}
		}
	}
	vpTokenJSON, err := json.Marshal(vpToken)
	if err != nil {
		return "", false, fmt.Errorf("failed to marshal vp_token: %w", err)
	}

	// OID4VP 1.0 §8.3: direct_post.jwt is never answered in plaintext, even
	// when the verifier omitted its metadata.
	var encryptResponse bool
	switch mode {
	case string(OAuthAuthzReqResponseModeDirectPostJWT):
		encryptResponse = true
	case string(OAuthAuthzReqResponseModeDirectPost):
		encryptResponse = false
	case "":
		encryptResponse = verifierEncryptionRequested(metadata)
	default:
		return "", false, fmt.Errorf("response_mode %q is not supported for a DCQL response", mode)
	}

	// OID4VP direct_post requires application/x-www-form-urlencoded
	formData := url.Values{}
	if encryptResponse {
		// The JWE is sent as the "response" parameter.
		jarmToken, err := p.createJARMResponse(vpTokenJSON, state, metadata)
		if err != nil {
			return "", false, fmt.Errorf("failed to create encrypted authorization response: %w", err)
		}
		formData.Set("response", jarmToken)
	} else {
		formData.Set("vp_token", string(vpTokenJSON))
		if state != "" {
			formData.Set("state", state)
		}
	}

	respBody, err := postAuthorizationResponse(ctx, p.httpClient(), endpoint, formData)
	if err != nil {
		return "", encryptResponse, fmt.Errorf("failed to send presentation to verifier: %w", err)
	}
	return redirectURIFromVerifierResponse(respBody), encryptResponse, nil
}

// redirectURIFromVerifierResponse reads the redirect_uri member of a Response
// Endpoint answer (OID4VP 1.0 §8.2), or "" when there is none.
func redirectURIFromVerifierResponse(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var verifierResponse struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal(body, &verifierResponse); err != nil {
		return ""
	}
	return verifierResponse.RedirectURI
}
