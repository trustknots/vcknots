package oid4vp

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
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
	ctx        context.Context
	req        *CredentialPresentationRequest
	httpClient *http.Client
	allowHTTP  bool
	// options are the profile Options this parse applies; Draft 24 parses
	// keep the zero value.
	options                 profile.Options
	x509TrustChainRoots     *x509.CertPool
	insecureSkipX509Verify  bool
	requestObjectValidation *RequestObjectValidationOptions
	expectedClientID        string
	// expectedClientIDAbsent records that the caller passed a Request Object
	// by value and named no outer client_id to compare it with. The client_id
	// claim is still authenticated against the signer.
	expectedClientIDAbsent bool
	// sentWalletNonce is the wallet_nonce this parse sent with a request_uri
	// POST, which the Request Object must echo (OID4VP 1.0 §5.10.1).
	sentWalletNonce string
	// admittedAt is the instant this parse authenticates the Request Object
	// at, pinned by the first requestObjectValidationOptions call so every
	// check of the parse reads the same clock. readmitAt, when set, is the
	// instant of the sealed admission a re-admission replays: the Request
	// Object's own exp, iat and nbf are judged at it (claimsAt), while the
	// certificate chain, its revocation, a Verifier Attestation and a Trust
	// Chain are judged at admittedAt, the current instant.
	admittedAt    time.Time
	readmitAt     time.Time
	requestSource requestSource
	// requestURI is the request_uri the Request Object was fetched from, ""
	// unless requestSource is sourceReference.
	requestURI string
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
	// draft24JARM selects the JARM response encryption rules of Draft 24
	// §8.3 instead of OpenID4VP 1.0 §8.3.
	draft24JARM bool
	// preRegistry is the presenter's registry of pre-registered clients, nil
	// when it has none. preRegisteredClient is the registry entry of this
	// request's pre-registered Client Identifier, nil for every other prefix.
	preRegistry         *preRegisteredRegistry
	preRegisteredClient *PreRegisteredClient
	// queryParams are the plain parameters of a sourceQuery parse, kept for
	// AdmitUnderVersion.
	queryParams map[string][]string
	// resolvedDefinition is the Presentation Definition a Draft 24 parse
	// fetched from presentation_definition_uri (or took from its seal), which
	// Seal records; nil otherwise.
	resolvedDefinition *resolvedDefinition
}

// preRegisteredRegistry is where a pre-registered Client Identifier is
// resolved (OID4VP 1.0 §5.9.2, Draft 24 §5.10.2): the map first, then the
// resolver.
type preRegisteredRegistry struct {
	clients map[string]PreRegisteredClient
	resolve PreRegisteredClientResolver
}

func newRequestCore() requestCore {
	return requestCore{
		req: &CredentialPresentationRequest{
			OAuthAuthzRequest: &OAuthAuthzRequest{},
			ClientMetadata:    &VerifierMetadata{},
		},
	}
}

// applySource records the outer client_id of a Request Object passed by value
// (types.RequestObjectSource).
func (c *requestCore) applySource(clientID string) {
	c.expectedClientID = clientID
	c.expectedClientIDAbsent = clientID == ""
}

// context returns the context this parse's outbound requests run under.
func (c *requestCore) context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
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

// requestURIPostSettings are the parameters of a request_uri POST (OID4VP 1.0
// §5.10, Draft 24 §5.11): the wallet_metadata to send (nil omits it), the
// wallet_nonce generator (nil uses defaultRequestURINonce) and whether the
// wallet_nonce is omitted altogether.
type requestURIPostSettings struct {
	walletMetadata map[string]any
	newNonce       func() (string, error)
	omitNonce      bool
}

// fetchRequestObjectByReference fetches the Request Object of a request_uri
// (OID4VP 1.0 §5.10, Draft 24 §5.11) and records that this parse observed
// delivery by reference. RequestObjectValidationOptions.RequestURIPolicy
// decides first whether the request_uri belongs to the outer client_id. A POST
// carries a fresh wallet_nonce, which the Request Object must echo (§5.10.1),
// unless post.omitNonce leaves it out; it carries post.walletMetadata as
// wallet_metadata when that is non-nil.
func (c *requestCore) fetchRequestObjectByReference(uri string, method RequestURIMethod, post requestURIPostSettings, accept string) ([]byte, error) {
	if err := c.applyRequestURIPolicy(uri); err != nil {
		return nil, err
	}
	form := url.Values{}
	if method == RequestURIMethodPOST {
		if !post.omitNonce {
			newNonce := post.newNonce
			if newNonce == nil {
				newNonce = defaultRequestURINonce
			}
			nonce, err := newNonce()
			if err != nil {
				return nil, fmt.Errorf("failed to generate wallet_nonce: %w", err)
			}
			if nonce == "" {
				return nil, errors.New("failed to generate wallet_nonce: the generator returned an empty value")
			}
			c.sentWalletNonce = nonce
			form.Set("wallet_nonce", nonce)
		}
		if post.walletMetadata != nil {
			metadataJSON, err := json.Marshal(post.walletMetadata)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal wallet_metadata: %w", err)
			}
			form.Set("wallet_metadata", string(metadataJSON))
		}
	}
	body, err := c.fetchRequestObject(uri, method, form, accept)
	if err != nil {
		return nil, err
	}
	c.requestSource = sourceReference
	c.requestURI = uri
	return body, nil
}

// applyRequestURIPolicy runs RequestObjectValidationOptions.RequestURIPolicy,
// when one is set, on the request_uri a Request Object was (or, for a
// re-admission, had been) fetched from and the outer client_id.
func (c *requestCore) applyRequestURIPolicy(uri string) error {
	if c.requestObjectValidation == nil || c.requestObjectValidation.RequestURIPolicy == nil {
		return nil
	}
	if err := c.requestObjectValidation.RequestURIPolicy(c.expectedClientID, uri); err != nil {
		return newAuthorizationRequestError(InvalidRequestError, "%w: %w", ErrRequestURINotAssociated, err)
	}
	return nil
}

// defaultRequestURINonce returns 32 random bytes, base64url-encoded without
// padding (OID4VP 1.0 §5.10: "a base64url-encoded, fresh, cryptographically
// random number with sufficient entropy").
func defaultRequestURINonce() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
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
	// RFC 9101 §4: the claims are a JSON object; null decodes to none.
	if claims == nil {
		return nil, nil, newAuthorizationRequestError(InvalidRequestError, "request object claims must be a JSON object")
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
	if c.admittedAt.IsZero() {
		c.admittedAt = requestObjectNow(options)
	}
	admittedAt := c.admittedAt
	options.Now = func() time.Time { return admittedAt }
	return options, nil
}

// claimsAt is the instant the Request Object's exp, iat and nbf are judged
// at: the instant of the sealed admission a re-admission replays, and now
// otherwise. Nothing else reads it; trust decisions use the current clock.
func (c *requestCore) claimsAt(now time.Time) time.Time {
	if !c.readmitAt.IsZero() {
		return c.readmitAt
	}
	return now
}

// admissionInstant is the instant a sealed record of this parse names: the
// sealed instant for a re-admission, so sealing a re-admitted handle again
// never moves it forward, and the parse's own instant otherwise.
func (c *requestCore) admissionInstant() time.Time {
	return c.claimsAt(c.admittedAt)
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
		Now:              c.claimsAt(now),
		ClockSkew:        options.ClockSkew,
		RequireExpiry:    options.RequireExpiry,
		MaxAge:           options.MaxAge,
	}
	return policy
}

// applyRequestObjectX5CRules enforces Options.RequestObjectX5C (HAIP §5):
// "The X.509 certificate of the trust anchor MUST NOT be included in the x5c
// JOSE header of the signed request. The X.509 certificate signing the
// request MUST NOT be self-signed."
func (c *requestCore) applyRequestObjectX5CRules(certificates []*x509.Certificate, options RequestObjectValidationOptions) error {
	rules := c.options.RequestObjectX5C
	if rules.RejectSelfSigned {
		if err := commonX509.RequireNonSelfSignedLeaf(certificates, "request object"); err != nil {
			return err
		}
	}
	if !rules.ExcludeAnchor {
		return nil
	}
	anchored, err := commonX509.ContainsTrustAnchor(certificates, options.TrustAnchors, options.RootCAs)
	if err != nil {
		return err
	}
	if anchored {
		return fmt.Errorf("%w forbids including the trust anchor certificate in the x5c header", profile.Refused("RequestObjectX5C.ExcludeAnchor"))
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
// Experimental.InsecureSkipX509Verify mode, which checks only the
// binding and the signature. c.req must already hold the request parameters.
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
	if err := c.applyRequestObjectX5CRules(certificates, options); err != nil {
		return err
	}
	if err := bindX509ClientID(clientID, certificates[0], c.req); err != nil {
		return err
	}
	verified := make(commonJOSE.Claims)
	if err := commonJOSE.VerifyClaims(parsed, certificates[0].PublicKey, &verified); err != nil {
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
