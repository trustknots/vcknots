package oid4vp

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// OID4VPClientIDPrefixWebOrigin is the effective Client Identifier Prefix the
// Wallet assigns to an unsigned DC API request, from the platform-authenticated
// Origin (OID4VP 1.0 Appendix A.2). It is never accepted from a request.
const OID4VPClientIDPrefixWebOrigin OID4VPClientIDPrefix = "web-origin"

// dcapiSignatureVerifier verifies one DC API request object signature with the
// authenticated leaf certificate's public key and returns the signed claims.
type dcapiSignatureVerifier func(publicKey any) (map[string]any, error)

// newDCAPIRequestBuilder wires the presenter's trust and profile policy into a
// requestBuilder used by the DC API paths.
func (p *Oid4vpPresenter) newDCAPIRequestBuilder(ctx context.Context, normalizedProfile profile.Profile) *requestBuilder {
	b := NewRequestBuilder()
	b.profile = normalizedProfile
	p.configureCore(ctx, &b.requestCore)
	b.errorResponseAllowed = false
	return b
}

// ParseDCAPIRequest authenticates and admits one platform DC API invocation
// (OID4VP 1.0 Appendix A.3). The Origin is supplied by the platform and is
// never read from the request. Unsigned requests are accepted without a
// signature using web-origin:<origin> as the effective identifier; signed and
// multi-signed requests are authenticated exactly like a signed Request
// Object. The result is an *AdmittedRequest whose response SubmitDCQLResponse
// returns as SubmitResult.DCAPIResponse.
func (p *Oid4vpPresenter) ParseDCAPIRequest(ctx context.Context, invocation types.DCAPIInvocation) (types.AdmittedRequest, error) {
	request, err := p.parseDCAPIRequest(ctx, invocation)
	if err != nil {
		return nil, err
	}
	return asAdmitted(p.admit(request, wireOpenID4VP1, dcapiRequestObject(invocation.Request)))
}

func (p *Oid4vpPresenter) parseDCAPIRequest(ctx context.Context, invocation types.DCAPIInvocation) (*CredentialPresentationRequest, error) {
	normalizedProfile, err := p.normalizedProfile()
	if err != nil {
		return nil, err
	}
	origin := strings.TrimSpace(invocation.Origin)
	if origin == "" {
		return nil, newAuthorizationRequestError(InvalidRequestError, "the platform Origin is required for a DC API request")
	}

	var request *CredentialPresentationRequest
	switch invocation.Request.Protocol {
	case DCAPIProtocolUnsigned:
		request, err = p.parseDCAPIUnsigned(ctx, invocation, origin, normalizedProfile)
	case DCAPIProtocolSigned:
		request, err = p.parseDCAPISigned(ctx, invocation, origin, normalizedProfile)
	case DCAPIProtocolMultiSigned:
		request, err = p.parseDCAPIMultiSigned(ctx, invocation, origin, normalizedProfile)
	default:
		return nil, newAuthorizationRequestError(InvalidRequestError, "unsupported DC API protocol %q", invocation.Request.Protocol)
	}
	if err != nil {
		return nil, err
	}
	// OID4VP 1.0 Appendix A.4: "The audience for the response (for example, the
	// aud value in a Key Binding JWT) MUST be the Origin, prefixed with
	// origin:". This is the case even for signed requests.
	request.ResponseAudience = dcapiOriginAudience(origin)
	request.DCAPIProtocol = invocation.Request.Protocol
	return request, nil
}

// dcapiRequestObject returns the signed request member of a DC API request
// (a compact JWS or a JWS JSON Serialization), or "" for an unsigned one.
func dcapiRequestObject(request types.DCAPIRequest) string {
	if request.Protocol == DCAPIProtocolUnsigned {
		return ""
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(request.Data, &data); err != nil {
		return ""
	}
	var compact string
	if err := json.Unmarshal(data["request"], &compact); err == nil {
		return compact
	}
	return string(data["request"])
}

// parseDCAPIUnsigned handles Appendix A.3.1. The Wallet MUST ignore any
// client_id and expected_origins delivered in an unsigned request (A.2).
func (p *Oid4vpPresenter) parseDCAPIUnsigned(ctx context.Context, invocation types.DCAPIInvocation, origin string, normalizedProfile profile.Profile) (*CredentialPresentationRequest, error) {
	if len(invocation.Request.Data) == 0 || string(invocation.Request.Data) == "null" {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API unsigned request data is required")
	}
	var params map[string]any
	if err := json.Unmarshal(invocation.Request.Data, &params); err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API unsigned request data must be a JSON object: %v", err)
	}
	// A.2: "The client_id parameter MUST be omitted in unsigned requests
	// defined in Appendix A.3.1. The Wallet MUST ignore any client_id parameter
	// that is present in an unsigned request." The same applies to
	// expected_origins: "This parameter is not for use in unsigned requests and
	// therefore a Wallet MUST ignore this parameter if it is present in an
	// unsigned request."
	delete(params, "client_id")
	delete(params, "expected_origins")
	params["client_id"] = dcapiWebOriginClientID(origin)

	b := p.newDCAPIRequestBuilder(ctx, normalizedProfile)
	b.requestSource = sourceDCAPIUnsigned
	b.setParamsWithAnyMap(params)
	if b.errValidation == nil {
		b.errValidation = b.validate()
	}
	return b.Build()
}

// parseDCAPISigned handles Appendix A.3.2.1: data.request is a compact JWS
// whose protected header or payload carries client_id.
func (p *Oid4vpPresenter) parseDCAPISigned(ctx context.Context, invocation types.DCAPIInvocation, origin string, normalizedProfile profile.Profile) (*CredentialPresentationRequest, error) {
	var data map[string]json.RawMessage
	if err := json.Unmarshal(invocation.Request.Data, &data); err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API signed request data must be a JSON object: %v", err)
	}
	rawRequest, ok := data["request"]
	if !ok {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API signed request must carry a request member")
	}
	var obj string
	if err := json.Unmarshal(rawRequest, &obj); err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API signed request member must be a compact JWS string")
	}
	if strings.Count(obj, ".") != 2 || len(obj) > maxRequestObjectBytes {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API signed request must be a bounded compact signed JWT")
	}

	b := p.newDCAPIRequestBuilder(ctx, normalizedProfile)
	options, err := b.requestObjectValidationOptions()
	if err != nil {
		return nil, err
	}
	parsed, err := jwt.ParseSigned(obj, resolveRequestObjectAlgorithms(options))
	if err != nil {
		return nil, fmt.Errorf("failed to parse DC API request object JWT: %w: %w", err, ErrRequestObjectSignatureInvalid)
	}
	if len(parsed.Headers) != 1 {
		return nil, fmt.Errorf("DC API request object JWT must have one protected header: %w", ErrRequestObjectTypInvalid)
	}
	typ, _ := parsed.Headers[0].ExtraHeaders["typ"].(string)
	if typ != "oauth-authz-req+jwt" {
		return nil, fmt.Errorf("DC API request object JWT 'typ' header must be 'oauth-authz-req+jwt': %w", ErrRequestObjectTypInvalid)
	}
	header, err := decodeDCAPIProtectedHeader(compactProtectedSegment(obj))
	if err != nil {
		return nil, fmt.Errorf("failed to decode DC API request object protected header: %w", err)
	}
	claims := map[string]any{}
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode DC API request object claims: %w", err)
	}
	clientID := dcapiClientIDFromHeaderOrPayload(header, claims)
	if clientID == "" {
		return nil, newAuthorizationRequestError(InvalidRequestError, "signed DC API request must carry client_id")
	}
	certificates, err := commonX509.DecodeX5CFromJWTHeader(obj)
	if err != nil {
		return nil, err
	}
	now := requestObjectNow(options)
	chainResult, err := b.verifyRequestObjectCertificateChain(certificates, options, now)
	if err != nil {
		return nil, fmt.Errorf("DC API request object certificate chain is not trusted: %w", err)
	}
	verify := func(publicKey any) (map[string]any, error) {
		verified := commonJOSE.Claims{}
		if err := parsed.Claims(publicKey, &verified); err != nil {
			return nil, fmt.Errorf("failed to verify DC API request object signature: %w: %w", err, ErrRequestObjectSignatureInvalid)
		}
		return map[string]any(verified), nil
	}
	b.requestSource = sourceDCAPISigned
	return b.finishDCAPIRequestObject(certificates, options, chainResult, clientID, verify, origin)
}

// parseDCAPIMultiSigned handles Appendix A.3.2.2. Each entry in the JWS JSON
// Serialization signatures array carries its own client_id in the protected
// header; the Wallet authenticates the first signature whose x509_hash client
// identifier it can verify and MUST verify at least one.
func (p *Oid4vpPresenter) parseDCAPIMultiSigned(ctx context.Context, invocation types.DCAPIInvocation, origin string, normalizedProfile profile.Profile) (*CredentialPresentationRequest, error) {
	var data map[string]json.RawMessage
	if err := json.Unmarshal(invocation.Request.Data, &data); err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API multi-signed request data must be a JSON object: %v", err)
	}
	rawRequest, ok := data["request"]
	if !ok {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API multi-signed request must carry a request member")
	}
	var multi struct {
		Payload    string `json:"payload"`
		Signatures []struct {
			Protected string `json:"protected"`
			Signature string `json:"signature"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(rawRequest, &multi); err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API multi-signed request must be a JWS JSON Serialization object")
	}
	if multi.Payload == "" || len(multi.Signatures) == 0 {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API multi-signed request requires payload and signatures")
	}
	initialBuilder := p.newDCAPIRequestBuilder(ctx, normalizedProfile)
	options, err := initialBuilder.requestObjectValidationOptions()
	if err != nil {
		return nil, err
	}
	parsed, err := jose.ParseSigned(string(rawRequest), resolveRequestObjectAlgorithms(options))
	if err != nil {
		return nil, fmt.Errorf("failed to parse DC API multi-signed request: %w", err)
	}
	if len(parsed.Signatures) != len(multi.Signatures) {
		return nil, errors.New("DC API multi-signed request signatures could not be parsed")
	}

	var lastErr error
	for index := range multi.Signatures {
		header, headerErr := decodeDCAPIProtectedHeader(multi.Signatures[index].Protected)
		if headerErr != nil {
			lastErr = headerErr
			continue
		}
		clientID, _ := header["client_id"].(string)
		if clientID == "" {
			lastErr = errors.New("DC API multi-signed signature is missing client_id")
			continue
		}
		clientIDValue, parseErr := parseOID4VPClientID(clientID)
		if parseErr != nil {
			lastErr = parseErr
			continue
		}
		if clientIDValue.prefix != OID4VPClientIDPrefixX509Hash && clientIDValue.prefix != OID4VPClientIDPrefixX509SanDNS {
			lastErr = errors.New("DC API multi-signed client identifier has no configured authentication method")
			continue
		}
		certificates, certErr := commonX509.DecodeX5CChain(header["x5c"])
		if certErr != nil {
			lastErr = certErr
			continue
		}
		b := p.newDCAPIRequestBuilder(ctx, normalizedProfile)
		now := requestObjectNow(options)
		chainResult, chainErr := b.verifyRequestObjectCertificateChain(certificates, options, now)
		if chainErr != nil {
			lastErr = chainErr
			continue
		}
		verify := func(publicKey any) (map[string]any, error) {
			verifiedIndex, _, payload, verifyErr := parsed.VerifyMulti(publicKey)
			if verifyErr != nil {
				return nil, fmt.Errorf("failed to verify DC API multi-signed request: %w: %w", verifyErr, ErrRequestObjectSignatureInvalid)
			}
			if verifiedIndex != index {
				return nil, errors.New("verified DC API signature does not match the authenticated Client Identifier")
			}
			// commonJOSE.Claims keeps JSON numbers exact: a NumericDate or a
			// DCQL value must not round through float64.
			claims := commonJOSE.Claims{}
			if unmarshalErr := json.Unmarshal(payload, &claims); unmarshalErr != nil {
				return nil, fmt.Errorf("failed to decode DC API multi-signed payload: %w", unmarshalErr)
			}
			return claims, nil
		}
		b.requestSource = sourceDCAPISigned
		request, finishErr := b.finishDCAPIRequestObject(certificates, options, chainResult, clientID, verify, origin)
		if finishErr != nil {
			lastErr = finishErr
			continue
		}
		return request, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no authenticatable signature")
	}
	return nil, fmt.Errorf("no trusted DC API multi-signed request signature: %w", lastErr)
}

// finishDCAPIRequestObject completes a signed DC API request: it verifies the
// selected signature, enforces the DC API and profile constraints, validates
// the standard claims and records the authentication result.
func (b *requestBuilder) finishDCAPIRequestObject(certificates []*x509.Certificate, options RequestObjectValidationOptions, chainResult *commonX509.SigningChainResult, clientID string, verify dcapiSignatureVerifier, origin string) (*CredentialPresentationRequest, error) {
	if len(certificates) == 0 {
		// DecodeX5CChain bounds every decoded chain; this guards the shared
		// helper against a caller that assembled one by other means.
		return nil, errors.New("x5c header must contain between 1 and 16 certificates")
	}
	verified, err := verify(certificates[0].PublicKey)
	if err != nil {
		return nil, err
	}
	if payloadClientID, ok := verified["client_id"].(string); ok && payloadClientID != "" && payloadClientID != clientID {
		authzErr := newAuthorizationRequestError(InvalidRequestError, "DC API signature client_id does not match the request object client_id")
		return nil, fmt.Errorf("%w: %w", authzErr, ErrRequestObjectClientIDMismatch)
	}
	verified["client_id"] = clientID
	parsedClientID, err := parseOID4VPClientID(clientID)
	if err != nil {
		return nil, err
	}
	if parsedClientID.prefix != OID4VPClientIDPrefixX509Hash && parsedClientID.prefix != OID4VPClientIDPrefixX509SanDNS {
		return nil, errors.New("signed DC API request client identifier has no configured authentication method")
	}
	if err := b.rejectTrustAnchorInX5C(certificates, options); err != nil {
		return nil, err
	}
	if err := bindDCAPIX509ClientID(parsedClientID, certificates[0]); err != nil {
		return nil, err
	}
	if err := validateDCAPIExpectedOrigins(verified, origin); err != nil {
		return nil, err
	}
	now := requestObjectNow(options)
	if err := validateRequestObjectClaims(commonJOSE.Claims(verified), b.resolveClaimPolicy(options, now)); err != nil {
		return nil, fmt.Errorf("JWT standard claims validation failed: %w", err)
	}
	b.setParamsWithAnyMap(verified)
	if b.errValidation == nil {
		b.errValidation = b.validate()
	}
	b.req.RequestObjectVerification = &RequestObjectVerification{
		ClientID: b.req.ClientID, CertificateSHA256: chainResult.Fingerprints,
		RevocationChecked:      chainResult.Revocation.CheckedCertificates,
		RevocationUnadvertised: chainResult.Revocation.NoMechanismCertificates,
		ExpiresAt:              requestObjectExpiry(commonJOSE.Claims(verified)),
		Certificate:            describeRequestObjectCertificate(certificates[0]),
	}
	return b.Build()
}

// dcapiResponse builds the object returned to the platform for an admitted DC
// API request (OID4VP 1.0 Appendix A.4). dc_api returns the plaintext vp_token
// object; dc_api.jwt encrypts the Authorization Response as direct_post.jwt
// does (§8.3) and returns it as the response member.
func (p *Oid4vpPresenter) dcapiResponse(request *CredentialPresentationRequest, vpToken map[string][]string) (*types.DCAPIResponse, bool, error) {
	if len(vpToken) == 0 {
		return nil, false, errors.New("DC API response requires a non-empty vp_token")
	}
	switch request.ResponseMode {
	case OAuthAuthzReqResponseModeDCAPI:
		return &types.DCAPIResponse{Protocol: request.DCAPIProtocol, Data: map[string]any{"vp_token": vpToken}}, false, nil
	case OAuthAuthzReqResponseModeDCAPIJWT:
		payload, err := json.Marshal(map[string]any{"vp_token": vpToken})
		if err != nil {
			return nil, false, fmt.Errorf("failed to marshal authorization response: %w", err)
		}
		encrypted, err := p.encryptAuthorizationResponseJWE(payload, request.ClientMetadata)
		if err != nil {
			return nil, false, fmt.Errorf("failed to encrypt DC API response: %w", err)
		}
		return &types.DCAPIResponse{Protocol: request.DCAPIProtocol, Data: map[string]any{"response": encrypted}}, true, nil
	default:
		return nil, false, fmt.Errorf("response_mode %q is not a DC API mode", request.ResponseMode)
	}
}

// bindDCAPIX509ClientID binds an x509_hash or x509_san_dns Client Identifier to
// the selected leaf. The DC API has no response URI; the Origin is checked
// against expected_origins instead. The SAN match is exact, never wildcard.
func bindDCAPIX509ClientID(clientID *OID4VPClientID, leaf *x509.Certificate) error {
	switch clientID.prefix {
	case OID4VPClientIDPrefixX509Hash:
		if err := commonX509.RequireLeafThumbprint(leaf, clientID.original); err != nil {
			return fmt.Errorf("%w: %w", err, ErrX509HashMismatch)
		}
		return nil
	case OID4VPClientIDPrefixX509SanDNS:
		if err := commonX509.RequireLeafDNSName(leaf, clientID.original, false); err != nil {
			return fmt.Errorf("%w: %w", err, ErrRequestObjectClientIDMismatch)
		}
		return nil
	default:
		return fmt.Errorf("unsupported DC API client_id prefix: %s", clientID.prefix)
	}
}

// validateDCAPIExpectedOrigins enforces Appendix A.2: expected_origins is
// REQUIRED for signed requests and the platform Origin MUST match one entry,
// otherwise the Wallet MUST return an error.
func validateDCAPIExpectedOrigins(claims map[string]any, origin string) error {
	raw, present := claims["expected_origins"]
	if !present {
		return newAuthorizationRequestError(InvalidRequestError, "expected_origins is required for signed DC API requests")
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return newAuthorizationRequestError(InvalidRequestError, "expected_origins must be a non-empty array of origins")
	}
	for _, value := range list {
		candidate, ok := value.(string)
		if !ok {
			return newAuthorizationRequestError(InvalidRequestError, "expected_origins must contain only strings")
		}
		if candidate == origin || strings.TrimRight(candidate, "/") == strings.TrimRight(origin, "/") {
			return nil
		}
	}
	return newAuthorizationRequestError(InvalidRequestError, "the platform Origin does not match any expected_origins entry")
}

// dcapiClientIDFromHeaderOrPayload returns client_id from the protected header
// when present, otherwise from the signed payload (Appendix A.3.2).
func dcapiClientIDFromHeaderOrPayload(header, claims map[string]any) string {
	if clientID, ok := header["client_id"].(string); ok && clientID != "" {
		return clientID
	}
	clientID, _ := claims["client_id"].(string)
	return clientID
}

func compactProtectedSegment(obj string) string {
	if index := strings.IndexByte(obj, '.'); index >= 0 {
		return obj[:index]
	}
	return ""
}

func decodeDCAPIProtectedHeader(encoded string) (map[string]any, error) {
	if encoded == "" {
		return nil, errors.New("protected header is empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	header := map[string]any{}
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, err
	}
	return header, nil
}

func dcapiWebOriginClientID(origin string) string {
	return string(OID4VPClientIDPrefixWebOrigin) + ":" + origin
}

func dcapiOriginAudience(origin string) string {
	return string(OID4VPClientIDPrefixOriginal) + ":" + origin
}
