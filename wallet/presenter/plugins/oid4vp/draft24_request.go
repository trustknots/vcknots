package oid4vp

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/trustknots/vcknots/wallet/profile"
)

// draft24RequestBuilder parses and authenticates one OpenID4VP Draft 24
// Authorization Request, which carries a Presentation Exchange
// presentation_definition, by value or by reference. A Draft 24 dcql_query is
// refused (VersionMismatchError). Draft 24 is outside every protocol profile,
// so HAIP never applies here.
type draft24RequestBuilder struct {
	requestCore
	// supportedTransactionDataTypes lists the transaction_data types the
	// wallet processes (Draft 24 Section 5.1).
	supportedTransactionDataTypes []string
	// requestURIPost are the presenter's request_uri POST settings (Draft 24
	// Section 5.11).
	requestURIPost requestURIPostSettings
	// sealedDefinition is the Presentation Definition a sealed admission
	// recorded for its presentation_definition_uri, nil otherwise.
	sealedDefinition *resolvedDefinition
}

func newDraft24RequestBuilder() *draft24RequestBuilder {
	core := newRequestCore()
	// Draft 24 authenticated an X.509 Request Object without reading aud; a
	// caller opts into the check by naming its WalletAudience.
	core.audienceOptional = true
	core.draft24JARM = true
	return &draft24RequestBuilder{requestCore: core}
}

// parseDraft24ClientID parses a client_id with the Client Identifier Scheme
// syntax of Draft 24 §5.10: "<client_id_scheme>:<orig_client_id>", with a
// Client Identifier without ":" referencing a pre-registered client (§5.10.2).
// Only the schemes Draft 24 §5.10.4 defines are accepted: redirect_uri,
// https (an OpenID Federation Entity Identifier, reported with the 1.0
// openid_federation prefix so both wire contracts reach one federation
// authentication), verifier_attestation and x509_san_dns. did and
// x509_san_uri are defined but not implemented, and are refused with
// ErrRequestObjectClientAuthUnsupported. web-origin belongs to the Digital
// Credentials API, which the Draft 24 entry points do not serve. The OpenID4VP
// 1.0 prefixes x509_hash, decentralized_identifier, openid_federation and
// origin are not Draft 24 schemes.
func parseDraft24ClientID(clientID string) (*OID4VPClientID, error) {
	trimmed := strings.TrimSpace(clientID)
	if trimmed == "" {
		return nil, fmt.Errorf("invalid client_id format")
	}
	scheme, original, found := strings.Cut(trimmed, ":")
	if !found {
		// Draft 24 §5.10.2: "If a : character is not present in the Client
		// Identifier, the Wallet MUST treat the Client Identifier as
		// referencing a pre-registered client."
		return &OID4VPClientID{original: trimmed, prefix: OID4VPClientIDPrefixPreRegistered}, nil
	}
	switch scheme {
	case "https":
		// Draft 24 §5.10.4: "Since the Entity Identifier is already defined
		// to start with https:, this Client Identifier Scheme MUST NOT be
		// prefixed additionally."
		return &OID4VPClientID{original: trimmed, prefix: OID4VPClientIDPrefixOIDFederation}, nil
	case "redirect_uri", "verifier_attestation", "x509_san_dns":
		original = strings.TrimSpace(original)
		if original == "" || strings.HasPrefix(original, scheme+":") {
			return nil, fmt.Errorf("invalid client_id: malformed %s Client Identifier", scheme)
		}
		return &OID4VPClientID{original: original, prefix: OID4VPClientIDPrefix(scheme)}, nil
	case "did", "x509_san_uri":
		return nil, fmt.Errorf("%w: the Draft 24 Client Identifier Scheme %q is not supported", ErrRequestObjectClientAuthUnsupported, scheme)
	case "web-origin":
		// Draft 24 §5.10.4: "The Wallet MUST NOT accept this Client
		// Identifier Scheme if the request is not sent via the Digital
		// Credentials API."
		return nil, fmt.Errorf("client_id scheme 'web-origin' is only valid over the Digital Credentials API: %w", ErrClientIDPrefixReserved)
	default:
		// Draft 24 §5.10.1: "If the Wallet does not support the Client
		// Identifier Scheme, the Wallet MUST refuse the request."
		return nil, fmt.Errorf("client_id scheme %q is not a Draft 24 Client Identifier Scheme", scheme)
	}
}

// ParseDraft24OID4VPClientID parses a client_id that arrived over the Draft 24
// wire contract, with the Client Identifier Schemes of Draft 24 §5.10. An
// "https" Client Identifier names an OpenID Federation Entity Identifier and
// is reported with OID4VPClientIDPrefixOIDFederation.
func ParseDraft24OID4VPClientID(clientID string) (*OID4VPClientID, error) {
	return parseDraft24ClientID(clientID)
}

func (b *draft24RequestBuilder) parseClientID(clientID string) (*OID4VPClientID, error) {
	return parseDraft24ClientID(clientID)
}

func (b *draft24RequestBuilder) validate() error {
	if b.errValidation != nil {
		return b.errValidation
	}
	// Draft 24 Section 5.1 names three ways to express the Presentation
	// Definition - by value, by reference in presentation_definition_uri, or
	// through a scope the Wallet maps to one - besides DCQL. Build resolves
	// a reference once the request is authenticated; mapping a scope is the
	// Wallet's own step after admission.
	hasDefinition := b.req.PresentationDefinition != nil && b.req.PresentationDefinition.ID != ""
	hasDefinitionReference := b.req.PresentationDefinitionURI != "" || b.req.Scope != ""
	if !hasDefinition && !hasDefinitionReference {
		return newAuthorizationRequestError(InvalidRequestError, "presentation_definition, presentation_definition_uri or scope is required for Draft24")
	}
	if b.req.ResponseType == "" {
		return newAuthorizationRequestError(InvalidRequestError, "response_type is required")
	}
	if b.req.ClientID == "" {
		return newAuthorizationRequestError(InvalidRequestError, "client_id is required")
	}
	dcAPIMode := isDCAPIMode(b.req.ResponseMode)
	if dcAPIMode {
		return newAuthorizationRequestError(InvalidRequestError, "response_mode %s is only valid over the Digital Credentials API", b.req.ResponseMode)
	}
	if !isDirectPostMode(b.req.ResponseMode) && b.req.RedirectURI == "" {
		return newAuthorizationRequestError(InvalidRequestError, "redirect_uri is required")
	}
	if b.req.Nonce == "" {
		return newAuthorizationRequestError(InvalidRequestError, "%w", ErrNonceRequired)
	}
	if isDirectPostMode(b.req.ResponseMode) {
		if _, err := parseResponseURI(b.req.ResponseURI, b.allowHTTP); err != nil {
			return newAuthorizationRequestError(InvalidRequestError, "%v", err)
		}
	}
	return nil
}

// WithQueryParams populates the request from URL query parameters.
func (b *draft24RequestBuilder) WithQueryParams(params map[string][]string) *draft24RequestBuilder {
	if b.errValidation != nil {
		return b
	}
	b.requestSource = sourceQuery
	b.queryParams = params

	singleParams := make(map[string]any)
	for key, values := range params {
		if len(values) > 1 {
			b.errValidation = fmt.Errorf("multiple values provided for parameter: %s", key)
			return b
		}
		singleParams[key] = values[0]
	}

	if value, isString := singleParams["client_id"].(string); isString {
		parsed, err := b.parseClientID(strings.TrimSpace(value))
		if err == nil && parsed.RequiresRequestObjectSignature() {
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%w", ErrRequestObjectSignatureRequired)
			return b
		}
		b.errorResponseAllowed = err == nil && parsed.prefix == OID4VPClientIDPrefixRedirectURI
	}

	b.setParams(singleParams)

	if err := b.validate(); err != nil {
		b.errValidation = err
		return b
	}
	return b
}

// WithRequestObjectURI fetches the Request Object from request_uri and
// authenticates it. A POST carries a fresh wallet_nonce the Request Object
// must echo, and the presenter's WalletMetadata as wallet_metadata when set
// (Draft 24 Section 5.11).
func (b *draft24RequestBuilder) WithRequestObjectURI(uri string, method RequestURIMethod) *draft24RequestBuilder {
	if b.errValidation != nil {
		return b
	}
	accept := "application/oauth-authz-req+jwt, application/jwt, text/plain, */*"
	if method == RequestURIMethodPOST {
		// Draft 24 Section 5.11: "the accept header set to
		// application/oauth-authz-req+jwt".
		accept = "application/oauth-authz-req+jwt"
	}
	body, err := b.fetchRequestObjectByReference(uri, method, b.requestURIPost, accept)
	if err != nil {
		b.errValidation = err
		return b
	}
	return b.withRequestObject(string(body))
}

// WithRequestObject authenticates a Request Object passed by value.
func (b *draft24RequestBuilder) WithRequestObject(obj string) *draft24RequestBuilder {
	b.requestSource = sourceValue
	return b.withRequestObject(obj)
}

// Build returns the admitted request, or the first refusal.
func (b *draft24RequestBuilder) Build() (*CredentialPresentationRequest, error) {
	if b.errValidation != nil {
		return nil, b.errValidation
	}
	if err := b.checkPreRegisteredClient(); err != nil {
		return nil, err
	}
	if err := b.validateResponseEncryptionMetadata(); err != nil {
		b.errorResponseAllowed = false
		return nil, err
	}
	if b.req.RequestObjectVerification != nil {
		b.req.RequestObjectVerification.Delivery = b.requestSource.delivery()
	}
	if err := b.resolvePresentationDefinitionURI(); err != nil {
		return nil, err
	}
	if b.req.ClientMetadata != nil {
		// Draft 24 is outside every 1.0 profile; its encrypted responses
		// follow JARM (Draft 24 §8.3).
		b.req.ClientMetadata.admitDraft24JARM()
	}
	return b.req, nil
}

// setParams sets the request fields from the Draft 24 Authorization Request
// parameters, recording the first refusal in b.errValidation. Draft 24
// tolerates non-string values and keeps the redirect URI the Client
// Identifier implies.
func (b *draft24RequestBuilder) setParams(params map[string]any) {
	if b.errValidation != nil {
		return
	}
	params = withoutIssuerClaim(params)

	// The version decision comes before every rule of Draft 24 alone (see
	// VersionMismatchError): a dcql_query request is answered as OpenID4VP
	// 1.0 or not at all.
	if err := versionMismatch(profile.VersionDraft24, params); err != nil {
		b.errValidation = err
		return
	}
	// Draft 24 §5.1: "Exactly one of the following parameters MUST be present
	// in the Authorization Request: dcql_query, presentation_definition,
	// presentation_definition_uri, or a scope value representing a
	// Presentation Definition"; §6 (invalid_request): "The request contains
	// more than one out of the following three options".
	present := []string{}
	for _, name := range []string{"dcql_query", "presentation_definition", "presentation_definition_uri"} {
		if _, exists := params[name]; exists {
			present = append(present, name)
		}
	}
	if len(present) > 1 {
		b.errValidation = newAuthorizationRequestError(InvalidRequestError, "only one of %s may be present", strings.Join(present, " and "))
		return
	}

	missing := []string{}
	getParam := func(key string, required bool) string {
		if val, exists := params[key]; exists {
			if strVal, ok := val.(string); ok {
				return strVal
			}
			return fmt.Sprintf("%v", val)
		}
		if required {
			missing = append(missing, key)
		}
		return ""
	}

	b.req.ResponseType = getParam("response_type", true)
	b.req.ClientID = strings.TrimSpace(getParam("client_id", true))
	if b.expectedClientID != "" && b.req.ClientID != b.expectedClientID {
		b.errValidation = fmt.Errorf("outer client_id does not match request object client_id: %s != %s: %w", b.expectedClientID, b.req.ClientID, ErrRequestObjectClientIDMismatch)
		return
	}

	redirectURIFromParam := getParam("redirect_uri", false)
	redirectURIFromClientID := ""
	if cid := b.req.ClientID; cid != "" {
		parsedCID, err := b.parseClientID(cid)
		if err != nil {
			b.errValidation = fmt.Errorf("invalid client_id: %w", err)
			return
		}
		switch parsedCID.prefix {
		case OID4VPClientIDPrefixRedirectURI:
			// Draft 24 §5.10.4: the Client Identifier "is the Verifier's
			// Redirect URI (or Response URI when Response Mode direct_post is
			// used)".
			redirectURIFromClientID = parsedCID.original
		case OID4VPClientIDPrefixX509SanDNS, OID4VPClientIDPrefixOIDFederation, OID4VPClientIDPrefixVerifierAttestation:
			// Bound by what authenticates the Verifier: the certificate's DNS
			// name, the Trust Chain metadata or the attestation.
		case OID4VPClientIDPrefixPreRegistered:
			// Draft 24 §5.10.2: the client must be known in advance; the
			// registration is checked in checkPreRegisteredClient.
			registered, lookupErr := b.lookupPreRegisteredClient(parsedCID.original)
			if lookupErr != nil {
				b.errValidation = lookupErr
				return
			}
			b.preRegisteredClient = registered
		default:
			b.errValidation = fmt.Errorf("unsupported client_id scheme: %s", parsedCID.prefix)
			return
		}
	}

	if redirectURIFromParam != "" && redirectURIFromClientID != "" && redirectURIFromParam != redirectURIFromClientID {
		if mode, _ := params["response_mode"].(string); isDirectPostMode(OAuthAuthzReqResponseMode(mode)) {
			// §8.2 refuses redirect_uri beside direct_post whatever its
			// value; the error goes to the Response URI the Client
			// Identifier binds.
			b.req.ResponseMode = OAuthAuthzReqResponseMode(mode)
			b.req.State, _ = params["state"].(string)
			b.req.ResponseURI = redirectURIFromClientID
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%w", ErrRedirectURIWithDirectPost)
			return
		}
		b.errValidation = fmt.Errorf("redirect_uri mismatch between parameter and one derived from client_id")
		return
	}

	b.req.RedirectURI = redirectURIFromParam
	if b.req.RedirectURI == "" {
		b.req.RedirectURI = redirectURIFromClientID
	}
	b.req.State = getParam("state", false)
	b.req.Nonce = getParam("nonce", true)
	b.req.Scope = getParam("scope", false)
	b.req.ResponseMode = OAuthAuthzReqResponseMode(getParam("response_mode", true))

	// Draft 24 §5.10.4: with the redirect_uri scheme "The Verifier MAY omit
	// the redirect_uri Authorization Request parameter (or response_uri when
	// Response Mode direct_post is used)."
	responseURIRequired := isDirectPostMode(b.req.ResponseMode) && redirectURIFromClientID == ""
	responseURIFromParam := getParam("response_uri", responseURIRequired)
	b.req.ResponseURI = responseURIFromParam
	// Draft 24 §8.2: "If the redirect_uri Authorization Request parameter is
	// present when the Response Mode is direct_post, the Wallet MUST return
	// an invalid_request Authorization Response error"; direct_post.jwt is
	// direct_post with JARM (§8.3.1).
	if isDirectPostMode(b.req.ResponseMode) && redirectURIFromParam != "" {
		b.req.RedirectURI = ""
		b.req.ResponseURI = redirectURIFromClientID
		b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%w", ErrRedirectURIWithDirectPost)
		return
	}
	if redirectURIFromClientID != "" && isDirectPostMode(b.req.ResponseMode) {
		b.req.RedirectURI = ""
		if responseURIFromParam == "" {
			b.req.ResponseURI = redirectURIFromClientID
		} else if responseURIFromParam != redirectURIFromClientID {
			// The refused response_uri is not the Verifier's, so the error
			// authorization response goes to the URI the Client Identifier
			// authenticates.
			b.req.ResponseURI = redirectURIFromClientID
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%w", ErrResponseURIClientIDMismatch)
			return
		}
	}

	b.req.PresentationDefinitionURI = getParam("presentation_definition_uri", false)
	if raw, exists := params["presentation_definition"]; exists {
		var data []byte
		var err error
		if value, ok := raw.(string); ok {
			data = []byte(value)
		} else {
			data, err = json.Marshal(raw)
		}
		if err == nil {
			err = b.req.setPresentationDefinition(data)
		}
		if err != nil {
			b.errValidation = fmt.Errorf("invalid presentation_definition: %w", err)
			return
		}
	}

	// Draft 24 §5.10.4: with the https scheme "The client_metadata
	// parameter, if present in the Authorization Request, MUST be ignored".
	if cm, exists := params["client_metadata"]; exists && cm != nil && !b.federationClient() {
		metadata, err := parseClientMetadataParam(cm, b.requireClientMetadataJWKKeyIDs, draft24Metadata)
		if err != nil {
			b.errValidation = err
			return
		}
		b.req.ClientMetadata = metadata
	}
	// Draft 24 §5.1: "Authoritative data the Wallet is able to obtain about
	// the Client from other sources ... take precedence over the values
	// passed in client_metadata", so a registration's metadata replaces it.
	if b.preRegisteredClient != nil && b.preRegisteredClient.Metadata != nil {
		registeredMetadata := *b.preRegisteredClient.Metadata
		b.req.ClientMetadata = &registeredMetadata
	}

	if len(missing) == 1 && missing[0] == "nonce" {
		b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%w", ErrNonceRequired)
	} else if len(missing) > 0 {
		b.errValidation = newAuthorizationRequestError(InvalidRequestError, "missing required parameters: %s", strings.Join(missing, ", "))
	}

	if td, exists := params["transaction_data"]; exists && td != nil && b.errValidation == nil {
		entries, err := parseTransactionDataParam(td)
		if err != nil {
			b.errValidation = err
			return
		}
		b.req.TransactionData = entries
		if err := b.validateTransactionData(); err != nil {
			b.errValidation = err
		}
	}
}

// validateTransactionData applies the rules of the 1.0 path to Draft 24
// transaction_data (Draft 24 Section 5.1): each credential_ids member names an
// input descriptor, and the credential it names must be an SD-JWT VC, whose
// Key Binding JWT is the only place the hashes can go (Draft 24 Appendix
// A.4.5). The descriptors of a definition passed by reference are checked
// once Build has resolved it.
func (b *draft24RequestBuilder) validateTransactionData() error {
	check := func(int, string) error { return nil }
	if len(b.req.RawPresentationDefinition) > 0 {
		formats, err := draft24DescriptorFormats(b.req.RawPresentationDefinition)
		if err != nil {
			return newAuthorizationRequestError(InvalidRequestError, "invalid presentation_definition: %v", err)
		}
		check = func(i int, id string) error {
			descriptorFormats, known := formats[id]
			if !known {
				return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].credential_ids references an unknown input descriptor", i)
			}
			if len(descriptorFormats) > 0 && !slices.ContainsFunc(descriptorFormats, isDraft24SDJWTFormat) {
				return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].credential_ids references an input descriptor whose formats %v cannot carry transaction data", i, descriptorFormats)
			}
			return nil
		}
	}
	alg, err := validateTransactionData(b.req.TransactionData, b.supportedTransactionDataTypes, check)
	if err != nil {
		return err
	}
	b.req.TransactionDataHashesAlg = alg
	return nil
}

// isDraft24SDJWTFormat reports whether format names an SD-JWT VC.
func isDraft24SDJWTFormat(format string) bool {
	return format == "vc+sd-jwt" || format == "dc+sd-jwt"
}

// draft24DescriptorFormats maps each input descriptor id of a Presentation
// Definition to the formats it accepts: its own format member, else the
// definition's, else none (any format).
func draft24DescriptorFormats(raw json.RawMessage) (map[string][]string, error) {
	var definition struct {
		Format           map[string]json.RawMessage `json:"format"`
		InputDescriptors []struct {
			ID     string                     `json:"id"`
			Format map[string]json.RawMessage `json:"format"`
		} `json:"input_descriptors"`
	}
	if err := json.Unmarshal(raw, &definition); err != nil {
		return nil, err
	}
	formats := make(map[string][]string, len(definition.InputDescriptors))
	for _, descriptor := range definition.InputDescriptors {
		accepted := descriptor.Format
		if len(accepted) == 0 {
			accepted = definition.Format
		}
		formats[descriptor.ID] = slices.Sorted(maps.Keys(accepted))
	}
	return formats, nil
}
