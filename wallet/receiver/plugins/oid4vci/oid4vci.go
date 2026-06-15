package oid4vci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

type Oid4vciReceiver struct{}

type credentialNonceResponse struct {
	CNonce *string `json:"c_nonce"`
	Nonce  *string `json:"nonce"`
}

var nonceHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
}

const maxNonceResponseBodyBytes int64 = 4 << 10

var oid4vciHTTPClient = &http.Client{Timeout: 15 * time.Second}

// OID4VCICredentialFormatToSerializationFlavor maps OID4VCI credential format identifiers
// to wallet serialization flavors.
func OID4VCICredentialFormatToSerializationFlavor(format string) (credential.SupportedSerializationFlavor, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "jwt_vc_json", "jwt_vc", string(credential.JwtVc):
		return credential.JwtVc, nil
	case "dc+sd-jwt", string(credential.SDJwtVC):
		return credential.SDJwtVC, nil
	default:
		return "", fmt.Errorf("unsupported credential format: %q", format)
	}
}

// doRequest performs an HTTP request and unmarshals the JSON response into target.
// It handles common patterns: URL construction, status checking, body reading, and JSON parsing.
func (o *Oid4vciReceiver) doRequest(method string, endpoint common.URIField, path string, body io.Reader, target interface{}) error {
	endpointURL := url.URL(endpoint)
	if !env.IsHTTPAllowed() && !strings.EqualFold(endpointURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	if path == "/.well-known/oauth-authorization-server" {
		// Special handling for metadata discovery as per RFC 8414 §3
		// The well-known string MUST be inserted between the host component and the path component.
		originalPath := strings.TrimSuffix(endpointURL.Path, "/")
		if !strings.HasPrefix(originalPath, path) {
			endpointURL.Path = path + originalPath
		}
	} else {
		// OID4VCI Draft 13 (ID1) §11.2.2, etc...
		if !strings.HasSuffix(endpointURL.Path, path) {
			endpointURL = *endpointURL.JoinPath(path)
		}
	}

	switch method {
	case "GET":
	case "POST":
		if body == nil {
			return fmt.Errorf("POST request requires a body")
		}
	default:
		return fmt.Errorf("unsupported HTTP method: %s", method)
	}

	req, err := http.NewRequest(method, endpointURL.String(), body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := oid4vciHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	if len(bodyBytes) == 0 {
		return fmt.Errorf("empty response body")
	}
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	return nil
}

func (o *Oid4vciReceiver) FetchIssuerMetadata(endpoint common.URIField, receivingTypes types.SupportedReceivingTypes) (*types.CredentialIssuerMetadata, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported serialization flavor")
	}

	var metadata types.CredentialIssuerMetadata
	if err := o.doRequest("GET", endpoint, "/.well-known/openid-credential-issuer", nil, &metadata); err != nil {
		return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
	}

	return &metadata, nil
}

func (o *Oid4vciReceiver) FetchAuthorizationServerMetadata(endpoint common.URIField, receivingTypes types.SupportedReceivingTypes) (*types.AuthorizationServerMetadata, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}

	var metadata types.AuthorizationServerMetadata
	if err := o.doRequest("GET", endpoint, "/.well-known/oauth-authorization-server", nil, &metadata); err != nil {
		return nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}

	return &metadata, nil
}

func (o *Oid4vciReceiver) FetchAccessToken(
	receivingTypes types.SupportedReceivingTypes,
	endpoint common.URIField,
	authzCode string,
	txCode string,
	opts ...types.TokenRequestOption,
) (*types.CredentialIssuanceAccessToken, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}
	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	formData.Set("pre-authorized_code", authzCode)
	if txCode != "" {
		formData.Set("tx_code", txCode)
	}
	endpointURLString := types.ResolveTokenEndpointURL(endpoint)
	endpointURL, err := url.Parse(endpointURLString)
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint URL: %w", err)
	}

	if !env.IsHTTPAllowed() && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpointURL.String(),
		strings.NewReader(formData.Encode()),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	requestConfig := types.NewTokenRequestConfig(opts...)
	if requestConfig.DPoPProof != "" {
		req.Header.Set("DPoP", requestConfig.DPoPProof)
	}
	resp, err := oid4vciHTTPClient.Do(req)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if isUseDPoPNonceResponse(resp, bodyBytes) {
			return nil, types.NewDPoPNonceError(resp.Header.Get("DPoP-Nonce"), types.ErrTokenRequestFailed)
		}
		if resp.StatusCode == http.StatusBadRequest {
			if errorCode := tokenErrorCode(bodyBytes); errorCode != "" {
				return nil, fmt.Errorf(
					"token request failed: %s; status: %d; response: %s: %w",
					errorCode,
					resp.StatusCode,
					string(bodyBytes),
					types.ErrTokenRequestFailed,
				)
			}
		}
		return nil, fmt.Errorf(
			"unexpected status code: %d response: %s",
			resp.StatusCode,
			string(bodyBytes),
		)
	}

	var accessToken types.CredentialIssuanceAccessToken
	if err := json.Unmarshal(bodyBytes, &accessToken); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return &accessToken, nil

}

func (o *Oid4vciReceiver) FetchNonce(receivingTypes types.SupportedReceivingTypes, endpoint common.URIField) (*string, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}

	nonceEndpointURL := url.URL(endpoint)
	if !env.IsHTTPAllowed() && !strings.EqualFold(nonceEndpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", nonceEndpointURL.Scheme)
	}

	req, err := http.NewRequest(http.MethodPost, nonceEndpointURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := nonceHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxNonceResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read nonce response: %w", err)
	}

	if int64(len(bodyBytes)) > maxNonceResponseBodyBytes {
		return nil, fmt.Errorf("nonce endpoint response exceeds %d bytes", maxNonceResponseBodyBytes)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("nonce endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("nonce endpoint returned empty response")
	}

	var nonceResponse credentialNonceResponse
	if err := json.Unmarshal(bodyBytes, &nonceResponse); err != nil {
		return nil, fmt.Errorf("failed to parse nonce response: %w", err)
	}

	if nonceResponse.CNonce != nil && *nonceResponse.CNonce != "" {
		return nonceResponse.CNonce, nil
	}
	if nonceResponse.Nonce != nil && *nonceResponse.Nonce != "" {
		return nonceResponse.Nonce, nil
	}

	return nil, fmt.Errorf("nonce response does not contain c_nonce or nonce")
}

func (o *Oid4vciReceiver) ReceiveCredential(
	receivingTypes types.SupportedReceivingTypes,
	endpoint common.URIField,
	credentialConfigurationID string,
	credentialIdentifier *string,
	accessToken types.CredentialIssuanceAccessToken,
	credentialDefinition *types.CredentialDefinition,
	jwtProof *string,
	options ...*types.CredentialRequestOptions,
) (*string, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}

	endpointURL := url.URL(endpoint)
	if !env.IsHTTPAllowed() && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	// Prepare credential request body
	reqBody := map[string]interface{}{}
	if credentialIdentifier != nil && *credentialIdentifier != "" {
		reqBody["credential_identifier"] = *credentialIdentifier
	} else {
		reqBody["credential_configuration_id"] = credentialConfigurationID
	}

	if jwtProof != nil {
		reqBody["proofs"] = map[string]interface{}{
			"jwt": []string{*jwtProof},
		}
	}

	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", endpointURL.String(), bytes.NewReader(reqBodyBytes))
	if err != nil {
		return nil, err
	}

	requestOptions := firstCredentialRequestOptions(options)

	// Set headers
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	tokenType := authorizationScheme(accessToken.TokenType)
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken.Token))
	if strings.EqualFold(accessToken.TokenType, "DPoP") {
		if requestOptions == nil || requestOptions.DPoPProofJWT == nil || *requestOptions.DPoPProofJWT == "" {
			return nil, fmt.Errorf("DPoP proof JWT is required for DPoP access token")
		}
		req.Header.Set("DPoP", *requestOptions.DPoPProofJWT)
	}
	req.Header.Set("Accept", "application/json")
	req.ContentLength = int64(len(reqBodyBytes))

	// Execute request
	resp, err := oid4vciHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		if isUseDPoPNonceResponse(resp, bodyBytes) {
			return nil, fmt.Errorf(
				"%w; status: %d; endpoint: %s; response: %s",
				types.NewDPoPNonceError(resp.Header.Get("DPoP-Nonce"), types.ErrUseDPoPNonce),
				resp.StatusCode,
				endpointURL.String(),
				string(bodyBytes),
			)
		}
		return nil, fmt.Errorf("failed to receive credential; status: %d; endpoint: %s; response: %s", resp.StatusCode, endpointURL.String(), string(bodyBytes))
	}

	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("credential response is empty")
	}

	// Extract credential from response
	var credentialResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &credentialResponse); err != nil {
		return nil, err
	}

	var credential interface{}

	credentialsRaw, hasCredentials := credentialResponse["credentials"]
	if hasCredentials {
		credentials, ok := credentialsRaw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("credentials response has invalid type")
		}
		if len(credentials) != 1 {
			return nil, fmt.Errorf("credentials response must contain exactly one credential, got %d", len(credentials))
		}
		credentialWrapper, ok := credentials[0].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("first credential entry has invalid format")
		}
		var found bool
		credential, found = credentialWrapper["credential"]
		if !found {
			return nil, fmt.Errorf("credential field missing in first credentials entry")
		}
	} else {
		var ok bool
		credential, ok = credentialResponse["credential"]
		if !ok {
			return nil, fmt.Errorf("no credential found in response")
		}
	}

	credentialStr, ok := credential.(string)
	if !ok {
		// If credential is not a string, marshal it back to JSON
		credentialBytes, err := json.Marshal(credential)
		if err != nil {
			return nil, err
		}
		credentialStr = string(credentialBytes)
	}

	return &credentialStr, nil
}

func firstCredentialRequestOptions(options []*types.CredentialRequestOptions) *types.CredentialRequestOptions {
	for _, option := range options {
		if option != nil {
			return option
		}
	}
	return nil
}

func authorizationScheme(tokenType string) string {
	switch {
	case strings.EqualFold(tokenType, "bearer"):
		return "Bearer"
	case strings.EqualFold(tokenType, "dpop"):
		return "DPoP"
	default:
		return cases.Title(language.English).String(strings.ToLower(tokenType))
	}
}

func tokenErrorCode(bodyBytes []byte) string {
	var errorResponse struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errorResponse); err != nil {
		return ""
	}
	return strings.TrimSpace(errorResponse.Error)
}

func isUseDPoPNonceError(bodyBytes []byte) bool {
	return tokenErrorCode(bodyBytes) == "use_dpop_nonce"
}

func isUseDPoPNonceResponse(resp *http.Response, bodyBytes []byte) bool {
	if isUseDPoPNonceError(bodyBytes) {
		return true
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "use_dpop_nonce")
}
