package oid4vp

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/common/observe"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// This file holds what the OpenID4VP 1.0 and Draft 24 request builders share:
// the per-parse state, the bounded request_uri fetch, Request Object decoding,
// X.509 Request Object authentication and client_metadata parsing. Each wire
// contract keeps its own parameter rules in its own builder.

// requestSource records how the Authorization Request parameters arrived.
type requestSource int

const (
	// sourceQuery is plain query parameters.
	sourceQuery requestSource = iota + 1
	// sourceValue is a Request Object passed by value (request=, or
	// ParseRequestObject).
	sourceValue
	// sourceReference is a Request Object fetched through request_uri.
	sourceReference
	// sourceDCAPIUnsigned and sourceDCAPISigned are Digital Credentials API
	// requests (OID4VP 1.0 Appendix A.3).
	sourceDCAPIUnsigned
	sourceDCAPISigned
)

// isDCAPI reports whether the request arrived through the DC API.
func (s requestSource) isDCAPI() bool {
	return s == sourceDCAPIUnsigned || s == sourceDCAPISigned
}

// delivery is the RequestObjectVerification.Delivery value for s.
func (s requestSource) delivery() string {
	switch s {
	case sourceQuery:
		return "query"
	case sourceValue:
		return "value"
	case sourceReference:
		return "reference"
	default:
		return ""
	}
}

// maxRequestObjectBytes bounds a Request Object, fetched or passed by value.
const maxRequestObjectBytes = 1 << 20

// requestCore is the state of one parse that both wire contracts use.
type requestCore struct {
	ctx                     context.Context
	req                     *CredentialPresentationRequest
	httpClient              *http.Client
	allowHTTP               bool
	profile                 profile.Profile
	x509TrustChainRoots     *x509.CertPool
	insecureSkipX509Verify  bool
	requestObjectValidation *RequestObjectValidationOptions
	expectedClientID        string
	// expectedClientIDAbsent records that the caller passed a Request Object
	// by value and named no outer client_id to compare it with. The client_id
	// claim is still authenticated against the signer.
	expectedClientIDAbsent bool
	// deliveredByReference and callerWalletNonce are the caller's statements
	// about a Request Object passed by value (types.RequestObjectSource).
	deliveredByReference bool
	callerWalletNonce    string
	// sentWalletNonce is the wallet_nonce the Request Object must echo
	// (OID4VP 1.0 §5.10.1): the one this parse sent, or the caller's.
	sentWalletNonce string
	requestSource   requestSource
	// requestObject is the Request Object the request was read from, "" for
	// plain parameters.
	requestObject string
	errValidation error
	// errorResponseAllowed marks a request whose Response URI a refusal may
	// name: plain query parameters with a redirect_uri Client Identifier,
	// which binds the Response URI (OID4VP 1.0 §5.9.3).
	errorResponseAllowed           bool
	requireClientMetadataJWKKeyIDs bool
	// audienceOptional skips the aud check when no WalletAudience is
	// configured.
	audienceOptional bool
}

func newRequestCore() requestCore {
	return requestCore{
		req: &CredentialPresentationRequest{
			OAuthAuthzRequest: &OAuthAuthzRequest{},
			ClientMetadata:    &VerifierMetadata{},
		},
		profile: profile.Final,
	}
}

// applySource records the caller's facts about a Request Object passed by
// value (types.RequestObjectSource).
func (c *requestCore) applySource(clientID string, src types.RequestObjectSource) {
	c.expectedClientID = clientID
	c.expectedClientIDAbsent = clientID == ""
	c.deliveredByReference = src.DeliveredByReference
	c.callerWalletNonce = src.WalletNonce
}

// context returns the context this parse's outbound requests run under.
func (c *requestCore) context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

// haipRequestObjectPolicy reports whether the HAIP Request Object rules apply.
func (c *requestCore) haipRequestObjectPolicy() bool {
	return c.profile.IsHAIP()
}

// isDirectPostMode reports whether the Response Mode delivers the Authorization
// Response to the Verifier's Response URI (OID4VP 1.0 §8.2), which is what
// binds response_uri to the Client Identifier in §5.9.3 and makes redirect_uri
// and response_uri mutually exclusive.
func isDirectPostMode(mode OAuthAuthzReqResponseMode) bool {
	return mode == OAuthAuthzReqResponseModeDirectPost || mode == OAuthAuthzReqResponseModeDirectPostJWT
}

// isDCAPIMode reports whether the Response Mode returns the response through
// the Digital Credentials API (OID4VP 1.0 Appendix A.2).
func isDCAPIMode(mode OAuthAuthzReqResponseMode) bool {
	return mode == OAuthAuthzReqResponseModeDCAPI || mode == OAuthAuthzReqResponseModeDCAPIJWT
}

// validateRedirectAndResponseURIExclusivity refuses a direct_post request that
// carries both redirect_uri and response_uri (OID4VP 1.0 §5.1, §8.2).
func validateRedirectAndResponseURIExclusivity(redirectURIFromParam, responseURIFromParam string) error {
	if redirectURIFromParam != "" && responseURIFromParam != "" {
		return newAuthorizationRequestError(InvalidRequestError, "redirect_uri and response_uri must not both be present in the same request")
	}
	return nil
}

// withoutIssuerClaim drops iss, which a Wallet must ignore in a Request Object
// (OID4VP 1.0 §5).
func withoutIssuerClaim(params map[string]any) map[string]any {
	if _, exists := params["iss"]; !exists {
		return params
	}
	filtered := make(map[string]any, len(params))
	for k, v := range params {
		if k != "iss" {
			filtered[k] = v
		}
	}
	return filtered
}

// parseClientMetadataParam decodes the client_metadata parameter, which
// arrives as a JSON object (Request Object claim) or a JSON string (query
// parameter).
func parseClientMetadataParam(cm any, requireKeyIDs bool) (*VerifierMetadata, error) {
	var rawMetadata []byte
	switch value := cm.(type) {
	case map[string]any:
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal client_metadata: %w", err)
		}
		rawMetadata = encoded
	case string:
		rawMetadata = []byte(value)
	default:
		return nil, fmt.Errorf("client_metadata must be a string or map")
	}
	var clientMeta VerifierMetadata
	if err := json.Unmarshal(rawMetadata, &clientMeta); err != nil {
		return nil, fmt.Errorf("invalid client_metadata: %w", err)
	}
	if requireKeyIDs {
		if err := validateClientMetadataJWKKeyIDs(rawMetadata); err != nil {
			return nil, newAuthorizationRequestError(InvalidRequestError, "%w", err)
		}
	}
	return &clientMeta, nil
}

// fetchRequestObject retrieves a Request Object from request_uri (OID4VP 1.0
// §5.10). The URI must use https unless HTTP is allowed for local tests,
// redirects are not followed and the body is bounded. form is the POST body;
// it is ignored for GET.
func (c *requestCore) fetchRequestObject(uri string, method RequestURIMethod, form url.Values, accept string) ([]byte, error) {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request_uri %q: %w", uri, err)
	}
	if !strings.EqualFold(parsedURI.Scheme, "https") && (!strings.EqualFold(parsedURI.Scheme, "http") || !c.allowHTTP) {
		return nil, fmt.Errorf("unsupported URL scheme for request_uri: %q (https required; explicit HTTP policy required for local tests)", parsedURI.Scheme)
	}

	ctx := observe.WithEndpoint(c.context(), observe.EndpointRequestObject)
	var req *http.Request
	switch method {
	case RequestURIMethodGET:
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, parsedURI.String(), nil)
	case RequestURIMethodPOST:
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, parsedURI.String(), strings.NewReader(form.Encode()))
	default:
		return nil, fmt.Errorf("unsupported request_uri_method: %s", method)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create %s request to %s: %w", method, uri, err)
	}
	req.Header.Set("User-Agent", "")
	req.Header.Set("Accept", accept)
	if method == RequestURIMethodPOST {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	// A redirect could move the fetch to plain http or to a host the scheme
	// check above never saw.
	resp, err := httpfetch.NoRedirect(c.httpClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send %s request to %s: %w", method, uri, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
	}
	body, err := httpfetch.ReadLimited(resp, maxRequestObjectBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read the request_uri response: %w", err)
	}
	return body, nil
}

// decodeRequestObject parses a Request Object as a bounded compact JWS with
// the typ header oauth-authz-req+jwt (RFC 9101 §5.2) and returns its
// unverified claims.
func decodeRequestObject(obj string, algorithms []jose.SignatureAlgorithm) (*jwt.JSONWebToken, commonJOSE.Claims, error) {
	// A compact JWS keeps every authentication parameter in the protected
	// header; the general JSON serialization's unprotected x5c is not read.
	if strings.Count(obj, ".") != 2 || len(obj) > maxRequestObjectBytes {
		return nil, nil, errors.New("request object must be a bounded compact signed JWT")
	}
	parsed, err := jwt.ParseSigned(obj, algorithms)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse request object JWT: %w: %w", err, ErrRequestObjectSignatureInvalid)
	}
	if len(parsed.Headers) != 1 {
		return nil, nil, fmt.Errorf("request object JWT must have one protected header: %w", ErrRequestObjectTypInvalid)
	}
	typ, exists := parsed.Headers[0].ExtraHeaders["typ"]
	if !exists {
		return nil, nil, fmt.Errorf("request object JWT must include 'typ' header parameter: %w", ErrRequestObjectTypInvalid)
	}
	if typ != "oauth-authz-req+jwt" {
		return nil, nil, fmt.Errorf("request object JWT 'typ' header must be 'oauth-authz-req+jwt': %w", ErrRequestObjectTypInvalid)
	}
	claims := make(commonJOSE.Claims)
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, nil, fmt.Errorf("failed to decode request object claims: %w", err)
	}
	return parsed, claims, nil
}

// requestObjectValidationOptions resolves the effective trust, time and
// signing policy from the explicit validation options and the upstream
// X509TrustChainRoots, refusing trust roots configured in both places.
// X509TrustChainRoots alone keeps its upstream revocation meaning: a
// certificate that advertises no revocation mechanism is accepted.
func (c *requestCore) requestObjectValidationOptions() (RequestObjectValidationOptions, error) {
	options := RequestObjectValidationOptions{RootCAs: c.x509TrustChainRoots, AllowUnadvertisedRevocation: true}
	if c.requestObjectValidation != nil {
		options = *c.requestObjectValidation
		if c.x509TrustChainRoots != nil && (options.RootCAs != nil || len(options.TrustAnchors) != 0) {
			return options, errors.New("configure Request Object trust roots in only one place")
		}
		if options.RootCAs == nil && len(options.TrustAnchors) == 0 {
			options.RootCAs = c.x509TrustChainRoots
		}
	}
	if options.ClockSkew < 0 {
		return options, errors.New("request object clock skew cannot be negative")
	}
	return options, nil
}

// adoptCallerWalletNonce takes the wallet_nonce the caller states it sent when
// it fetched a Request Object that now arrives by value, so the echo rule of
// OID4VP 1.0 §5.10.1 binds it. A nonce this parse sent itself always wins.
func (c *requestCore) adoptCallerWalletNonce() {
	if c.sentWalletNonce == "" && c.requestSource == sourceValue && c.callerWalletNonce != "" {
		c.sentWalletNonce = c.callerWalletNonce
	}
}

// verifyRequestObjectCertificateChain runs the configured X.509 chain and
// revocation checks for a leaf-first certificate list.
func (c *requestCore) verifyRequestObjectCertificateChain(certificates []*x509.Certificate, options RequestObjectValidationOptions, now time.Time) (*commonX509.SigningChainResult, error) {
	client := options.CRL.HTTPClient
	if client == nil {
		client = c.httpClient
		if client == nil {
			client = (&Oid4vpPresenter{}).httpClient()
		}
	}
	return commonX509.VerifySigningChainWithPolicy(c.context(), certificates, commonX509.SigningChainPolicy{
		TrustAnchors:                options.TrustAnchors,
		Roots:                       options.RootCAs,
		KeyUsages:                   options.CertificateKeyUsages,
		CRL:                         options.CRL,
		AllowUnadvertisedRevocation: options.AllowUnadvertisedRevocation,
		CurrentTime:                 now,
		HTTPClient:                  client,
	})
}

// resolveClaimPolicy resolves the caller's options against the active profile
// and wire contract.
func (c *requestCore) resolveClaimPolicy(options RequestObjectValidationOptions, now time.Time) requestObjectClaimPolicy {
	policy := requestObjectClaimPolicy{
		Audiences:        options.WalletAudience,
		AudienceOptional: c.audienceOptional && len(options.WalletAudience) == 0,
		Now:              now,
		ClockSkew:        options.ClockSkew,
		RequireExpiry:    options.RequireExpiry,
		MaxAge:           options.MaxAge,
	}
	if c.haipRequestObjectPolicy() && policy.MaxAge == 0 {
		// HAIP bounds the lifetime of a Request Object that does carry exp;
		// it does not require exp (see RequireExpiry).
		policy.MaxAge = haipRequestObjectMaxAge
	}
	return policy
}

// rejectTrustAnchorInX5C enforces HAIP §5 and §6.1.1: "The X.509 certificate
// of the trust anchor MUST NOT be included in the x5c JOSE header of the
// signed request." It is inert outside the HAIP profile.
func (c *requestCore) rejectTrustAnchorInX5C(certificates []*x509.Certificate, options RequestObjectValidationOptions) error {
	if !c.haipRequestObjectPolicy() {
		return nil
	}
	anchored, err := commonX509.ContainsTrustAnchor(certificates, options.TrustAnchors, options.RootCAs)
	if err != nil {
		return err
	}
	if anchored {
		return errors.New("HAIP forbids including the trust anchor certificate in the x5c header")
	}
	return nil
}

// requireWalletNonceEcho applies OID4VP 1.0 §5.10.1 to a signature-verified
// Request Object: "if the Wallet passed a wallet_nonce in the POST request,
// the Wallet MUST validate whether the request object contains the respective
// nonce value in a wallet_nonce claim. If it does not, the Wallet MUST
// terminate request processing."
func (c *requestCore) requireWalletNonceEcho(verified commonJOSE.Claims) error {
	if c.sentWalletNonce == "" {
		return nil
	}
	claimed, ok := verified["wallet_nonce"].(string)
	if !ok || claimed != c.sentWalletNonce {
		return newAuthorizationRequestError(InvalidRequestError, "%w", ErrRequestObjectWalletNonceMismatch)
	}
	return nil
}

// authenticateX509RequestObject authenticates an x509_san_dns or x509_hash
// Request Object: the Client Identifier binding to the leaf and the response
// endpoint (OID4VP 1.0 §5.9.3), the signature, the wallet_nonce echo, the
// claim policy and the certificate chain. verifyChain false is the
// InsecureSkipX509Verify mode, which checks only the binding and the
// signature. c.req must already hold the request parameters.
func (c *requestCore) authenticateX509RequestObject(obj string, parsed *jwt.JSONWebToken, options RequestObjectValidationOptions, verifyChain bool) error {
	clientID, err := parseOID4VPClientID(c.req.ClientID)
	if err != nil {
		return err
	}
	if clientID.prefix != OID4VPClientIDPrefixX509Hash && clientID.prefix != OID4VPClientIDPrefixX509SanDNS {
		// OID4VP 1.0 §5.1: client_metadata keys are never request-signature keys.
		return fmt.Errorf("%w: %q", ErrRequestObjectClientAuthUnsupported, clientID.prefix)
	}
	certificates, err := commonX509.DecodeX5CFromJWTHeader(obj)
	if err != nil {
		return err
	}
	if err := c.rejectTrustAnchorInX5C(certificates, options); err != nil {
		return err
	}
	if err := bindX509ClientID(clientID, certificates[0], c.req); err != nil {
		return err
	}
	verified := make(commonJOSE.Claims)
	if err := parsed.Claims(certificates[0].PublicKey, &verified); err != nil {
		return fmt.Errorf("failed to verify request object with x5c certificate: %w: %w", err, ErrRequestObjectSignatureInvalid)
	}
	if !verifyChain {
		return nil
	}
	if err := c.requireWalletNonceEcho(verified); err != nil {
		return err
	}
	now := requestObjectNow(options)
	if err := validateRequestObjectClaims(verified, c.resolveClaimPolicy(options, now)); err != nil {
		return fmt.Errorf("JWT standard claims validation failed: %w", err)
	}
	result, err := c.verifyRequestObjectCertificateChain(certificates, options, now)
	if err != nil {
		return fmt.Errorf("request object certificate chain is not trusted: %w", err)
	}
	c.req.RequestObjectVerification = &RequestObjectVerification{
		ClientID: c.req.ClientID, CertificateSHA256: result.Fingerprints,
		RevocationChecked:      result.Revocation.CheckedCertificates,
		RevocationUnadvertised: result.Revocation.NoMechanismCertificates,
		WalletNonce:            c.sentWalletNonce,
		ExpiresAt:              requestObjectExpiry(verified),
		Certificate:            describeRequestObjectCertificate(certificates[0]),
	}
	return nil
}

// bindX509ClientID binds an x509_hash or x509_san_dns Client Identifier to the
// signing leaf and, for x509_san_dns, the response endpoint's host to the
// DNS name. The SAN match is exact, never wildcard (OID4VP 1.0 §5.9.3).
func bindX509ClientID(clientID *OID4VPClientID, leaf *x509.Certificate, request *CredentialPresentationRequest) error {
	if clientID.prefix == OID4VPClientIDPrefixX509Hash {
		// OID4VP 1.0 §5.9.3 and HAIP §5: x509_hash does not imply a DNS binding.
		if err := commonX509.RequireLeafThumbprint(leaf, clientID.original); err != nil {
			return fmt.Errorf("%w: %w", err, ErrX509HashMismatch)
		}
		return nil
	}
	if err := commonX509.RequireLeafDNSName(leaf, clientID.original, false); err != nil {
		return fmt.Errorf("%w: %w", err, ErrRequestObjectClientIDMismatch)
	}
	uri, err := url.Parse(request.responseEndpoint())
	if err != nil || !strings.EqualFold(uri.Hostname(), clientID.original) {
		return fmt.Errorf("redirect_uri/response_uri and client_id (origin) must be same: %w", ErrRequestObjectClientIDMismatch)
	}
	return nil
}
