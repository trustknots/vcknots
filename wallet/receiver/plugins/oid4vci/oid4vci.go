package oid4vci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

type Oid4vciReceiver struct{}

func (o *Oid4vciReceiver) FetchIssuerMetadata(endpoint common.URIField, receivingTypes types.SupportedReceivingTypes) (*types.CredentialIssuerMetadata, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported serialization flavor")
	}

	metadataPath := "/.well-known/openid-credential-issuer"
	endpointURL := url.URL(endpoint)
	if !strings.HasSuffix(endpointURL.Path, metadataPath) {
		endpointURL.Path = endpointURL.Path + metadataPath
	}

	resp, err := http.Get(endpointURL.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch metadata")
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("metadata is empty")
	}

	var metadata types.CredentialIssuerMetadata
	if err := json.Unmarshal(bodyBytes, &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func (o *Oid4vciReceiver) FetchAuthorizationServerMetadata(endpoint common.URIField, receivingTypes types.SupportedReceivingTypes) (*types.AuthorizationServerMetadata, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}

	metadataPath := "/.well-known/oauth-authorization-server"
	endpointURL := url.URL(endpoint)
	if !strings.HasSuffix(endpointURL.Path, metadataPath) {
		endpointURL.Path = endpointURL.Path + metadataPath
	}

	resp, err := http.Get(endpointURL.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch authorization server metadata")
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("authorization server metadata is empty")
	}

	var metadata types.AuthorizationServerMetadata
	if err := json.Unmarshal(bodyBytes, &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func (o *Oid4vciReceiver) FetchAccessToken(receivingTypes types.SupportedReceivingTypes, endpoint common.URIField, authzCode string) (*types.CredentialIssuanceAccessToken, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}

	tokenPath := "/token"
	endpointURL := url.URL(endpoint)
	if !strings.HasSuffix(endpointURL.Path, tokenPath) {
		endpointURL.Path = endpointURL.Path + tokenPath
	}

	// Prepare form data for token request
	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	formData.Set("pre-authorized_code", authzCode)

	resp, err := http.PostForm(endpointURL.String(), formData)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch access token; status: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("access token response is empty")
	}

	var accessToken types.CredentialIssuanceAccessToken
	if err := json.Unmarshal(bodyBytes, &accessToken); err != nil {
		return nil, err
	}

	return &accessToken, nil
}

func (o *Oid4vciReceiver) ReceiveCredential(
	receivingTypes types.SupportedReceivingTypes,
	endpoint common.URIField,
	format string,
	accessToken types.CredentialIssuanceAccessToken,
	credentialDefinition *types.CredentialDefinition,
	jwtProof *string,
) (*string, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}

	endpointURL := url.URL(endpoint)

	// Prepare credential request body
	reqBody := map[string]interface{}{
		"format": format,
	}

	if credentialDefinition != nil {
		reqBody["credential_definition"] = credentialDefinition
	}

	if jwtProof != nil {
		reqBody["proof"] = map[string]interface{}{
			"proof_type": "jwt",
			"jwt":        *jwtProof,
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

	// Set headers
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	// Capitalize the token type (e.g., "bearer" -> "Bearer") for spec compliance
	tokenType := cases.Title(language.English).String(strings.ToLower(accessToken.TokenType))
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken.Token))
	req.Header.Set("Accept", "application/json")
	req.ContentLength = int64(len(reqBodyBytes))

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to receive credential; status: %d; endpoint: %s; response: %s", resp.StatusCode, endpointURL.String(), string(bodyBytes))
	}
	if err != nil {
		return nil, err
	}

	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("credential response is empty")
	}

	// Extract credential from response
	var credentialResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &credentialResponse); err != nil {
		return nil, err
	}

	credential, ok := credentialResponse["credential"]
	if !ok {
		return nil, fmt.Errorf("no credential found in response")
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
