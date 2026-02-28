package oid4vp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

type Oid4vpPresenter struct {
	X509TrustChainRoots     *x509.CertPool
	// InsecureSkipX509Verify skips certificate verification for testing purposes.
	// WARNING: This should NEVER be set to true in production environments.
	// This is only for conformance testing with self-signed or non-standard certificates.
	InsecureSkipX509Verify bool
}

// ParsePresentationRequest parses the presentation request URI and returns a CredentialPresentationRequest,
// following the flow defined in the OID4VP specification and RFC9101 (OAuth 2.0 with JAR).
//
// Verifier may provide an Authorization Request using either of three options:
// 1. request_uri (preferred): A URI that points to a JWT-encoded Authorization Request.
// 2. request: A JWT-encoded Authorization Request directly in the query parameter.
// 3. Query parameters: Individual parameters in the query string.
//
// This function detect which option is used and passes that to the proper handlers to obtain the CredentialPresentationRequest.
func (p *Oid4vpPresenter) ParsePresentationRequest(uriString string) (*CredentialPresentationRequest, error) {
	parsedURL, err := url.Parse(uriString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}
	queryParams := parsedURL.Query()

	// Early validation of client_id format (before fetching request_uri)
	// This prevents unnecessary network requests for obviously invalid client_ids
	if clientID := strings.TrimSpace(queryParams.Get("client_id")); clientID != "" {
		if _, err := parseOID4VPClientID(clientID); err != nil {
			return nil, fmt.Errorf("invalid client_id in initial request: %w", err)
		}
	}

	builder := NewRequestBuilder()
	builder.x509TrustChainRoots = p.X509TrustChainRoots
	builder.insecureSkipX509Verify = p.InsecureSkipX509Verify

	// Request Object by Reference
	if requestURI := queryParams.Get("request_uri"); requestURI != "" {
		method := RequestURIMethodGET // Default to GET if not specified
		if m := queryParams.Get("request_uri_method"); m != "" {
			switch strings.ToLower(m) {
			case "get":
				method = RequestURIMethodGET
			case "post":
				method = RequestURIMethodPOST
			default:
				return nil, fmt.Errorf("unsupported request_uri_method: %s", m)
			}
		}
		builder = builder.WithRequestObjectURI(requestURI, method)
	} else if requestObj := queryParams.Get("request"); requestObj != "" {
		builder = builder.WithRequestObject(requestObj)
	} else {
		builder = builder.WithQueryParams(queryParams)
	}

	req, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build CredentialPresentationRequest: %w", err)
	}

	return req, nil
}

// Present sends the presentation to the verifier
func (p *Oid4vpPresenter) Present(protocol types.SupportedPresentationProtocol, endpoint url.URL, serializedPresentation []byte, presentationSubmission types.PresentationSubmission, request *types.PresentationRequest) error {
	if protocol != types.Oid4vp {
		return fmt.Errorf("plugin type mismatch")
	}

	// Convert presentation_submission to JSON string for form data
	presentationSubmissionJSON, err := json.Marshal(presentationSubmission)
	if err != nil {
		return fmt.Errorf("failed to marshal presentation_submission: %w", err)
	}

	// Check if JARM (JWT-Secured Authorization Response Mode) is required
	var useJARM bool
	var encryptionAlg, encryptionEnc string
	var verifierJWKS *jose.JSONWebKeySet
	
	if request != nil && request.ClientMetadata != nil {
		if metadata, ok := request.ClientMetadata.(*VerifierMetadata); ok {
			if metadata.AuthorizationEncryptedResponseAlg != "" {
				useJARM = true
				encryptionAlg = metadata.AuthorizationEncryptedResponseAlg
				encryptionEnc = metadata.AuthorizationEncryptedResponseEnc
				verifierJWKS = &metadata.Jwks
			}
		}
	}

	// OID4VP direct_post requires application/x-www-form-urlencoded
	formData := url.Values{}

	if useJARM {
		// JARM: Create JWT with response parameters, encrypt it, and send as "response" parameter
		jarmToken, err := p.createJARMResponse(string(serializedPresentation), string(presentationSubmissionJSON), request, encryptionAlg, encryptionEnc, verifierJWKS)
		if err != nil {
			return fmt.Errorf("failed to create JARM response: %w", err)
		}
		formData.Set("response", jarmToken)
	} else {
		// Standard response: Send vp_token and presentation_submission directly
		formData.Set("vp_token", string(serializedPresentation))
		formData.Set("presentation_submission", string(presentationSubmissionJSON))

		// Add state if present in the original request
		if request != nil && request.State != "" {
			formData.Set("state", request.State)
		}
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Post(endpoint.String(), "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to send presentation to verifier: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("verifier returned non-200 status: %d, body: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// createJARMResponse creates a JWT-Secured Authorization Response (JARM)
func (p *Oid4vpPresenter) createJARMResponse(vpToken, presentationSubmission string, request *types.PresentationRequest, encAlg, encEnc string, verifierJWKS *jose.JSONWebKeySet) (string, error) {
	// Create the response payload
	payload := map[string]interface{}{
		"vp_token":               vpToken,
		"presentation_submission": presentationSubmission,
	}
	
	// Add state if present
	if request != nil && request.State != "" {
		payload["state"] = request.State
	}

	// Marshal payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JARM payload: %w", err)
	}

	// Find encryption key from verifier JWKS
	if verifierJWKS == nil || len(verifierJWKS.Keys) == 0 {
		return "", fmt.Errorf("verifier JWKS not available for encryption")
	}

	// Select appropriate key for encryption (prefer "enc" use, or first available key)
	var encryptionKey *jose.JSONWebKey
	for i := range verifierJWKS.Keys {
		key := &verifierJWKS.Keys[i]
		if key.Use == "enc" {
			encryptionKey = key
			break
		}
	}
	if encryptionKey == nil {
		// Use first key if no "enc" key found
		encryptionKey = &verifierJWKS.Keys[0]
	}

	// Parse algorithm
	var keyAlg jose.KeyAlgorithm
	switch encAlg {
	case "ECDH-ES":
		keyAlg = jose.ECDH_ES
	case "ECDH-ES+A128KW":
		keyAlg = jose.ECDH_ES_A128KW
	case "ECDH-ES+A192KW":
		keyAlg = jose.ECDH_ES_A192KW
	case "ECDH-ES+A256KW":
		keyAlg = jose.ECDH_ES_A256KW
	default:
		return "", fmt.Errorf("unsupported encryption algorithm: %s", encAlg)
	}

	var contentEnc jose.ContentEncryption
	switch encEnc {
	case "A128GCM":
		contentEnc = jose.A128GCM
	case "A192GCM":
		contentEnc = jose.A192GCM
	case "A256GCM":
		contentEnc = jose.A256GCM
	case "A128CBC-HS256":
		contentEnc = jose.A128CBC_HS256
	case "A192CBC-HS384":
		contentEnc = jose.A192CBC_HS384
	case "A256CBC-HS512":
		contentEnc = jose.A256CBC_HS512
	default:
		return "", fmt.Errorf("unsupported encryption encoding: %s", encEnc)
	}

	// Create encrypter
	encrypter, err := jose.NewEncrypter(
		contentEnc,
		jose.Recipient{
			Algorithm: keyAlg,
			Key:       encryptionKey.Key,
			KeyID:     encryptionKey.KeyID,
		},
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	// Encrypt the payload
	jwe, err := encrypter.Encrypt(payloadBytes)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt JARM payload: %w", err)
	}

	// Serialize to compact form
	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWE: %w", err)
	}

	return serialized, nil
}

type requestBuilder struct {
	req                    *CredentialPresentationRequest
	x509TrustChainRoots    *x509.CertPool
	insecureSkipX509Verify bool
	errValidation          error
}

func NewRequestBuilder() *requestBuilder {
	return &requestBuilder{
		req: &CredentialPresentationRequest{
			OAuthAuthzRequest:      &OAuthAuthzRequest{},
			ClientMetadata:         &VerifierMetadata{},
			PresentationDefinition: &PresentationDefinition{},
		},
		x509TrustChainRoots:    nil,
		insecureSkipX509Verify: false,
	}
}

func (b *requestBuilder) validate() error {
	if b.errValidation != nil {
		return b.errValidation
	}

	if b.req.PresentationDefinition == nil || b.req.PresentationDefinition.ID == "" {
		return fmt.Errorf("presentation_definition is required")
	}

	if b.req.ResponseType == "" {
		return fmt.Errorf("response_type is required")
	}

	if b.req.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}

	if b.req.RedirectURI == "" {
		return fmt.Errorf("redirect_uri is required")
	}

	if b.req.Nonce == "" {
		return fmt.Errorf("nonce is required")
	}

	return nil
}

// setParamsWithInterfaceMap sets the CredentialPresentationRequest fields from a map of any parameters,
// tracking any missing required parameters.
// Missing required parameters are recorded in b.errValidation and set as empty strings.
func (b *requestBuilder) setParamsWithAnyMap(params map[string]any) {
	if b.errValidation != nil {
		return
	}

	// OID4VP specification: MUST ignore 'iss' claim if present in Request Object
	// Remove 'iss' claim from params to ensure it's not processed
	if _, exists := params["iss"]; exists {
		// Create a copy of params without 'iss' claim
		filteredParams := make(map[string]any)
		for k, v := range params {
			if k != "iss" {
				filteredParams[k] = v
			}
		}
		params = filteredParams
	}

	missing := []string{}

	getParam := func(key string, required bool) string {
		if val, exists := params[key]; exists {
			if strVal, ok := val.(string); ok {
				return strVal
			}
			// Convert non-string values to string representation if possible
			return fmt.Sprintf("%v", val)
		}

		if required {
			missing = append(missing, key)
		}

		return ""
	}

	b.req.ResponseType = getParam("response_type", true)
	b.req.ClientID = strings.TrimSpace(getParam("client_id", true))

	redirectURIFromParam := getParam("redirect_uri", false) // redirect_uri may be emitted
	redirectURIFromClientID := ""
	if cid := b.req.ClientID; cid != "" {
		if parsedCID, err := parseOID4VPClientID(cid); err == nil {
			switch parsedCID.prefix {
			case OID4VPClientIDPrefixRedirectURI, OID4VPClientIDPrefixX509SanDNS:
				redirectURIFromClientID = parsedCID.original
			default: // unimplemented: other client_id prefixes
				b.errValidation = fmt.Errorf("unsupported client_id prefix: %s", parsedCID.prefix)
			}
		} else {
			b.errValidation = fmt.Errorf("invalid client_id: %w", err)
			return
		}
	}

	if redirectURIFromParam != "" && redirectURIFromClientID != "" && redirectURIFromParam != redirectURIFromClientID {
		b.errValidation = fmt.Errorf("redirect_uri mismatch between parameter and one derived from client_id")
		return
	}

	b.req.RedirectURI = redirectURIFromClientID
	b.req.Scope = getParam("scope", false)
	b.req.State = getParam("state", false)
	b.req.Nonce = getParam("nonce", true)

	b.req.ResponseMode = OAuthAuthzReqResponseMode(getParam("response_mode", true))

	b.req.ResponseURI = getParam("response_uri", b.req.ResponseMode == OAuthAuthzReqResponseModeDirectPost)

	if pd := getParam("presentation_definition", true); pd != "" {
		// Handle presentation_definition as either string (JSON) or map
		var presDef PresentationDefinition
		if pdMap, ok := params["presentation_definition"].(map[string]any); ok {
			if id, exists := pdMap["id"]; exists {
				presDef.ID = fmt.Sprintf("%v", id)
			}
		} else {
			if err := json.Unmarshal([]byte(pd), &presDef); err != nil {
				b.errValidation = fmt.Errorf("invalid presentation_definition: %w", err)
				return
			}
		}
		b.req.PresentationDefinition = &presDef
	}

	if cm, exists := params["client_metadata"]; exists && cm != nil {
		var clientMeta VerifierMetadata
		if cmMap, ok := cm.(map[string]any); ok {
			// Convert map to JSON and then unmarshal to struct
			jsonBytes, err := json.Marshal(cmMap)
			if err != nil {
				b.errValidation = fmt.Errorf("failed to marshal client_metadata: %w", err)
				return
			}
			if err := json.Unmarshal(jsonBytes, &clientMeta); err != nil {
				b.errValidation = fmt.Errorf("invalid client_metadata: %w", err)
				return
			}
		} else if cmStr, ok := cm.(string); ok {
			// Handle string format
			if err := json.Unmarshal([]byte(cmStr), &clientMeta); err != nil {
				b.errValidation = fmt.Errorf("invalid client_metadata: %w", err)
				return
			}
		} else {
			b.errValidation = fmt.Errorf("client_metadata must be a string or map")
			return
		}
		b.req.ClientMetadata = &clientMeta
	}

	if len(missing) > 0 {
		b.errValidation = fmt.Errorf("missing required parameters: %s", strings.Join(missing, ", "))
	}

	// TODO: support transaction_data and verifier_info
}

// WithQueryParams populates the CredentialPresentationRequest fields from URL query parameters.
func (b *requestBuilder) WithQueryParams(params map[string][]string) *requestBuilder {
	if b.errValidation != nil {
		return b
	}

	singleParams := make(map[string]any)
	for key, values := range params {
		if len(values) > 1 {
			b.errValidation = fmt.Errorf("multiple values provided for parameter: %s", key)
			return b
		}
		singleParams[key] = values[0]
	}

	b.setParamsWithAnyMap(singleParams)

	if err := b.validate(); err != nil {
		b.errValidation = err
		return b
	}

	return b
}

// WithRequestObject uses the provided JWT string as the request object
// to populate the CredentialPresentationRequest,
// validating its claims and signature as per OID4VP and RFC9101.
func (b *requestBuilder) WithRequestObject(obj string) *requestBuilder {
	if b.errValidation != nil {
		return b
	}

	// Parse the JWT
	allowedAlgs := []jose.SignatureAlgorithm{jose.ES256, jose.RS256}
	parsedJWT, err := jwt.ParseSigned(obj, allowedAlgs)
	if err != nil {
		b.errValidation = fmt.Errorf("failed to parse request object JWT: %w", err)
		return b
	}

	// Validate 'typ' header as per OID4VP specification
	// Request Objects MUST include typ Header Parameter with value "oauth-authz-req+jwt"
	if len(parsedJWT.Headers) == 0 {
		b.errValidation = fmt.Errorf("request object JWT must have headers")
		return b
	}

	typHeader, exists := parsedJWT.Headers[0].ExtraHeaders["typ"]
	if !exists {
		b.errValidation = fmt.Errorf("request object JWT must include 'typ' header parameter")
		return b
	}

	typStr, ok := typHeader.(string)
	if !ok || typStr != "oauth-authz-req+jwt" {
		b.errValidation = fmt.Errorf("request object JWT 'typ' header must be 'oauth-authz-req+jwt', got: %v", typHeader)
		return b
	}

	// extract claims without verification for initial processing
	claims := make(map[string]any)
	if err := parsedJWT.UnsafeClaimsWithoutVerification(&claims); err != nil {
		b.errValidation = fmt.Errorf("failed to get JWT claims: %w", err)
		return b
	}

	b.setParamsWithAnyMap(claims)

	if err := b.validate(); err != nil {
		b.errValidation = err
		return b
	}

	// x509_san_dns
	clientID, err := parseOID4VPClientID(b.req.ClientID)
	if err == nil && clientID.prefix == OID4VPClientIDPrefixX509SanDNS {
		var certificates *[]*x509.Certificate = nil
		
		if b.insecureSkipX509Verify {
			// For testing: Parse certificates from x5c WITHOUT calling x509.Verify(),
			// which in Go 1.20+ performs strict standards compliance checks that reject
			// non-compliant certificates (e.g., "OIDF Test" from conformance test suites).
			// We manually parse the x5c chain and use the certificates directly.

			// Split JWT to get header part
			parts := strings.Split(obj, ".")
			if len(parts) < 2 {
				b.errValidation = fmt.Errorf("invalid JWT format")
				return b
			}

			// Decode header (JWT uses base64url encoding without padding)
			headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				b.errValidation = fmt.Errorf("failed to decode JWT header: %w", err)
				return b
			}

			var header struct {
				X5C []string `json:"x5c"`
			}
			if err := json.Unmarshal(headerJSON, &header); err != nil {
				b.errValidation = fmt.Errorf("failed to parse JWT header: %w", err)
				return b
			}

			if len(header.X5C) == 0 {
				b.errValidation = fmt.Errorf("x5c header is empty")
				return b
			}

			// Parse all certificates in the x5c chain
			// x5c contains standard base64 encoded (not base64url) DER certificates
			var certChain []*x509.Certificate
			for i, certB64 := range header.X5C {
				certDER, err := base64.StdEncoding.DecodeString(certB64)
				if err != nil {
					b.errValidation = fmt.Errorf("failed to decode x5c certificate at index %d: %w", i, err)
					return b
				}
				cert, err := x509.ParseCertificate(certDER)
				if err != nil {
					b.errValidation = fmt.Errorf("failed to parse x5c certificate at index %d: %w", i, err)
					return b
				}
				certChain = append(certChain, cert)
			}

			certificates = &certChain
		} else {
			// Production: verify certificate chain
			certificateChains, err := parsedJWT.Headers[0].Certificates(x509.VerifyOptions{
				Roots: b.x509TrustChainRoots,
			})
			if err != nil {
				b.errValidation = err
				return b
			}

			for _, chain := range certificateChains {
				err = commonX509.CheckIfCertsRevoked(chain)
				if err == nil {
					b.errValidation = nil
					certificates = &chain
					break
				} else {
					b.errValidation = err
				}
			}
			if certificates == nil {
				return b
			}
		}

		// Request object must be verified with the leaf certificate in the x5c array (RFC 7515).
		claims := jwt.Claims{}
		verifyKey := (*certificates)[0].PublicKey
		if err := parsedJWT.Claims(verifyKey, &claims); err != nil {
			b.errValidation = fmt.Errorf("failed to verify request object with x5c certificate: %v", err)
			return b
		}

		// ClientID should contain DNS name which is same as the SAN of the leaf certificate in the x5c array (OID4VP x509_san_dns). #106
		matched := false
		for _, n := range (*certificates)[0].DNSNames {
			if clientID.original == n {
				matched = true
				break
			}
		}
		if !matched {
			b.errValidation = fmt.Errorf("SAN of the certificate and client_id did not match")
			return b
		}

		// response_uri / redirect_uri check #107
		var uri *url.URL
		if b.req.ResponseMode == "direct_post" {
			uri, err = url.Parse(b.req.ResponseURI)
			if err != nil {
				b.errValidation = fmt.Errorf("response_uri must be URI: %w", err)
				return b
			}
		} else {
			uri, err = url.Parse(b.req.RedirectURI)
			if err != nil {
				b.errValidation = fmt.Errorf("redirect_uri must be URI: %w", err)
				return b
			}
		}
		if hostname := uri.Hostname(); hostname != clientID.original {
			b.errValidation = fmt.Errorf("redirect_uri/response_uri and client_id (origin) must be same")
			return b
		}

		return b
	}

	// JWT signature verification is mandatory for JWT request objects as per RFC9101
	if b.req.ClientMetadata == nil {
		b.errValidation = fmt.Errorf("client_metadata is required for JWT request object verification")
		return b
	}

	// fetch the public key for signature verification
	k, err := b.req.ClientMetadata.FetchKeyWithKID(parsedJWT.Headers[0].KeyID)
	if err != nil {
		b.errValidation = fmt.Errorf("failed to fetch public key for JWT verification: %w", err)
		return b
	}

	// verify the JWT signature and extract standard claims for validation
	standardClaims := jwt.Claims{}
	if err := parsedJWT.Claims(&k, &standardClaims); err != nil {
		b.errValidation = fmt.Errorf("failed to verify JWT signature: %w", err)
		return b
	}

	// validate standard JWT claims as per RFC9101 and OID4VP requirements
	if err := standardClaims.Validate(jwt.Expected{
		Time: time.Now(), // validates exp, iat, nbf claims
	}); err != nil {
		b.errValidation = fmt.Errorf("JWT standard claims validation failed: %w", err)
		return b
	}

	// extract all verified claims for parameter processing
	verifiedClaims := make(map[string]any)
	if err := parsedJWT.Claims(&k, &verifiedClaims); err != nil {
		b.errValidation = fmt.Errorf("failed to extract verified claims: %w", err)
		return b
	}

	// re-set parameters from verified claims to ensure integrity
	b.setParamsWithAnyMap(verifiedClaims)

	if err := b.validate(); err != nil {
		b.errValidation = err
		return b
	}

	return b
}

// WithRequestObjectURI constructs the CredentialPresentationRequest
// with fetching the request object from the given URI using the specified method,
// and validates its claims and signature as per OID4VP and RFC9101.
func (b *requestBuilder) WithRequestObjectURI(uri string, method RequestURIMethod) *requestBuilder {
	if b.errValidation != nil {
		return b
	}

	var req *http.Request
	var err error

	switch method {
	case RequestURIMethodGET:
		req, err = http.NewRequest(http.MethodGet, uri, nil)
	case RequestURIMethodPOST:
		req, err = http.NewRequest(http.MethodPost, uri, nil)
	default:
		b.errValidation = fmt.Errorf("unsupported request_uri_method: %s", method)
		return b
	}

	if err != nil {
		b.errValidation = fmt.Errorf("failed to create %s request to %s: %w", method, uri, err)
		return b
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		b.errValidation = fmt.Errorf("failed to send %s request to %s: %w", method, uri, err)
		return b
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b.errValidation = fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
		return b
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		b.errValidation = fmt.Errorf("failed to read response body: %w", err)
		return b
	}

	return b.WithRequestObject(string(body))
}

func (b *requestBuilder) Build() (*CredentialPresentationRequest, error) {
	if b.errValidation != nil {
		return nil, b.errValidation
	}
	return b.req, nil
}

type OID4VPClientID struct {
	original string
	prefix   OID4VPClientIDPrefix
}

type OID4VPClientIDPrefix string

const (
	OID4VPClientIDPrefixRedirectURI         OID4VPClientIDPrefix = "redirect_uri"
	OID4VPClientIDPrefixOIDFederation       OID4VPClientIDPrefix = "openid_federation"
	OID4VPClientIDPrefixDID                 OID4VPClientIDPrefix = "decentralized_identifier"
	OID4VPClientIDPrefixVerifierAttestation OID4VPClientIDPrefix = "verifier_attestation"
	OID4VPClientIDPrefixX509SanDNS          OID4VPClientIDPrefix = "x509_san_dns"
	OID4VPClientIDPrefixX509Hash            OID4VPClientIDPrefix = "x509_hash"
	OID4VPClientIDPrefixOriginal            OID4VPClientIDPrefix = "origin"
)

// parseOID4VPClientID parses and validates the client_id according to OID4VP specification.
func parseOID4VPClientID(clientID string) (*OID4VPClientID, error) {
	// Syntax: <client_id_prefix>:<orig_client_id>

	// Trim whitespace from client_id
	clientID = strings.TrimSpace(clientID)

	parts := strings.SplitN(clientID, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid client_id format")
	}

	prefix := parts[0]
	origin := strings.TrimSpace(parts[1])

	// Detect duplicate prefix (e.g., "x509_san_dns:x509_san_dns:...")
	if strings.HasPrefix(origin, prefix+":") {
		return nil, fmt.Errorf("invalid client_id: duplicate prefix detected")
	}

	switch OID4VPClientIDPrefix(prefix) {
	case OID4VPClientIDPrefixRedirectURI,
		OID4VPClientIDPrefixOIDFederation,
		OID4VPClientIDPrefixDID,
		OID4VPClientIDPrefixVerifierAttestation,
		OID4VPClientIDPrefixX509SanDNS,
		OID4VPClientIDPrefixX509Hash:
		return &OID4VPClientID{
			original: origin,
			prefix:   OID4VPClientIDPrefix(prefix),
		}, nil
	case OID4VPClientIDPrefixOriginal:
		// The Wallet MUST NOT accept this Client Identifier Prefix in requests.
		return nil, fmt.Errorf("client_id prefix 'origin' is not allowed")
	default:
		return nil, fmt.Errorf("unsupported client_id prefix: %s", prefix)
	}
}
