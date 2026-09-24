package oid4vp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// setParamsWithAnyMap sets the request fields from the Authorization Request
// parameters, recording the first refusal in b.errValidation.
func (b *requestBuilder) setParamsWithAnyMap(params map[string]any) {
	if b.errValidation != nil {
		return
	}
	params = withoutIssuerClaim(params)

	missing := []string{}
	getParam := func(key string, required bool) string {
		if val, exists := params[key]; exists {
			if strVal, ok := val.(string); ok {
				return strVal
			}
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%s must be a string", key)
			return ""
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
		// Only the unsigned DC API path may carry the Wallet-synthesised
		// web-origin identifier (Appendix A.2).
		parsedCID, err := b.parseClientID(cid)
		if err != nil {
			b.errValidation = fmt.Errorf("invalid client_id: %w", err)
			return
		}
		switch parsedCID.prefix {
		case OID4VPClientIDPrefixRedirectURI:
			redirectURIFromClientID = parsedCID.original
		case OID4VPClientIDPrefixX509SanDNS, OID4VPClientIDPrefixX509Hash:
			// Bound to the signing certificate, not to a redirect URI.
		case OID4VPClientIDPrefixWebOrigin:
			// The DC API effective client identifier uses the platform
			// Origin; no redirect URI is derived (OID4VP 1.0 Appendix A.2).
		case OID4VPClientIDPrefixOIDFederation, OID4VPClientIDPrefixVerifierAttestation:
			// OID4VP 1.0 §5.9.3: the response endpoints are constrained by
			// what authenticates the Verifier (Trust Chain metadata, or the
			// attestation's redirect_uris), never derived from the Client
			// Identifier.
		case OID4VPClientIDPrefixPreRegistered:
			// OID4VP 1.0 §5.9.2: the client must be known in advance; the
			// registration is checked in checkPreRegisteredClient.
			registered, lookupErr := b.lookupPreRegisteredClient(parsedCID.original)
			if lookupErr != nil {
				b.errValidation = lookupErr
				return
			}
			b.preRegisteredClient = registered
		default:
			b.errValidation = fmt.Errorf("unsupported client_id prefix: %s", parsedCID.prefix)
		}
	}

	if redirectURIFromParam != "" && redirectURIFromClientID != "" && redirectURIFromParam != redirectURIFromClientID {
		b.errValidation = fmt.Errorf("redirect_uri mismatch between parameter and one derived from client_id")
		return
	}

	b.req.RedirectURI = redirectURIFromClientID
	if redirectURIFromParam != "" {
		b.req.RedirectURI = redirectURIFromParam
	}
	b.req.State = getParam("state", false)
	b.req.Nonce = getParam("nonce", true)
	b.req.ResponseMode = OAuthAuthzReqResponseMode(getParam("response_mode", true))

	// OID4VP 1.0 §5.9.3: with the redirect_uri prefix "the original Client
	// Identifier part ... is the Verifier's Redirect URI (or Response URI when
	// Response Mode direct_post is used)", and "The Verifier MAY omit the
	// redirect_uri Authorization Request parameter (or response_uri when
	// Response Mode direct_post is used)".
	responseURIRequired := isDirectPostMode(b.req.ResponseMode) && redirectURIFromClientID == ""
	responseURIFromParam := getParam("response_uri", responseURIRequired)

	// OID4VP 1.0 §8.2: redirect_uri and response_uri are mutually exclusive
	// when response_mode is direct_post (or direct_post.jwt).
	if isDirectPostMode(b.req.ResponseMode) {
		if err := validateRedirectAndResponseURIExclusivity(redirectURIFromParam, responseURIFromParam); err != nil {
			b.errValidation = err
			return
		}
	}

	b.req.ResponseURI = responseURIFromParam

	// OID4VP 1.0 §5.9.3 binds the Response URI to the redirect_uri Client
	// Identifier the same way it binds the Redirect URI, so a foreign
	// response_uri never receives the VP Token.
	if redirectURIFromClientID != "" && isDirectPostMode(b.req.ResponseMode) {
		if responseURIFromParam == "" {
			b.req.ResponseURI = redirectURIFromClientID
		} else if responseURIFromParam != redirectURIFromClientID {
			// The rejected response_uri is not the Verifier's, so the error
			// authorization response goes to the URI the Client Identifier
			// authenticates, never to the one the request chose.
			b.req.ResponseURI = redirectURIFromClientID
			b.errValidation = newAuthorizationRequestError(InvalidRequestError,
				"%w", ErrResponseURIClientIDMismatch)
			return
		}
		// §8.2: the response goes to the Response URI, so no Redirect URI is
		// used for this request.
		b.req.RedirectURI = ""
	}

	// OID4VP 1.0 Appendix A.2: the response is returned through the DC API, so
	// response_uri and redirect_uri MUST be absent from the request.
	if b.requestSource.isDCAPI() && isDCAPIMode(b.req.ResponseMode) {
		if redirectURIFromParam != "" || responseURIFromParam != "" {
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "redirect_uri and response_uri must not be present with response_mode %s", b.req.ResponseMode)
			return
		}
		b.req.RedirectURI = ""
		b.req.ResponseURI = ""
	}

	if b.requestSource == sourceQuery {
		if _, hasMethod := params["request_uri_method"]; hasMethod {
			// OID4VP 1.0 §5.1: "request_uri_method parameter MUST NOT be
			// present if a request_uri parameter is not present."
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "request_uri_method must not be present without request_uri")
			return
		}
	}

	// Presentation Exchange belongs to the Draft 24 entry points.
	for _, unsupported := range []string{"presentation_definition", "presentation_definition_uri", "presentation_submission"} {
		if _, exists := params[unsupported]; exists {
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%s is not supported; use dcql_query instead", unsupported)
			return
		}
	}

	// Requesting Credentials via the scope parameter is not supported by this wallet.
	if scope, exists := params["scope"]; exists {
		if scopeStr, ok := scope.(string); !ok || scopeStr != "" {
			b.errValidation = newAuthorizationRequestError(InvalidScopeError, "scope parameter is not supported; use dcql_query instead")
			return
		}
	}

	if cm, exists := params["client_metadata"]; exists && cm != nil {
		metadata, err := parseClientMetadataParam(cm, b.requireClientMetadataJWKKeyIDs)
		if err != nil {
			b.errValidation = err
			return
		}
		b.req.ClientMetadata = metadata
	}

	// A pre-registered Verifier's metadata is the registered one (OID4VP 1.0
	// §5.9.2); a request that also carries client_metadata is invalid_client
	// (§8.5).
	if b.preRegisteredClient != nil && b.preRegisteredClient.Metadata != nil {
		if cm, exists := params["client_metadata"]; exists && cm != nil {
			b.errValidation = newAuthorizationRequestError(InvalidClientError, "client_metadata must not be sent by a pre-registered client")
			return
		}
		registeredMetadata := *b.preRegisteredClient.Metadata
		b.req.ClientMetadata = &registeredMetadata
	}

	if rawDcqlQuery, exists := params["dcql_query"]; exists {
		dcqlQuery, err := parseDcqlQueryWithHAIP(rawDcqlQuery, b.profile.IsHAIP())
		if err != nil {
			b.errValidation = err
			return
		}
		b.req.DcqlQuery = dcqlQuery
	} else {
		missing = append(missing, "dcql_query")
	}

	if len(missing) == 1 && missing[0] == "nonce" {
		b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%w", ErrNonceRequired)
	} else if len(missing) > 0 {
		b.errValidation = newAuthorizationRequestError(InvalidRequestError, "missing required parameters: %s", strings.Join(missing, ", "))
	}

	if td, exists := params["transaction_data"]; exists && td != nil {
		entries, err := parseTransactionDataParam(td)
		if err != nil {
			b.errValidation = err
			return
		}
		b.req.TransactionData = entries
	}

	// transaction_data_hashes_alg travels inside each transaction_data object
	// (OID4VP 1.0 Appendix B.3.3.1); validateFinalTransactionData resolves it.
	if b.errValidation == nil && len(b.req.TransactionData) > 0 {
		if err := b.validateFinalTransactionData(); err != nil {
			b.errValidation = err
			return
		}
	}
}

// parseTransactionDataParam reads the transaction_data parameter: an array of
// strings, or its JSON serialization in application/x-www-form-urlencoded.
func parseTransactionDataParam(td any) ([]string, error) {
	switch v := td.(type) {
	case []any:
		entries := make([]string, 0, len(v))
		for _, item := range v {
			str, ok := item.(string)
			if !ok {
				return nil, newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data entries must be base64url strings")
			}
			entries = append(entries, str)
		}
		return entries, nil
	case []string:
		return v, nil
	case string:
		var entries []string
		if err := json.Unmarshal([]byte(v), &entries); err != nil {
			return nil, newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data must be a JSON array of strings")
		}
		return entries, nil
	default:
		return nil, newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data must be an array of strings")
	}
}

// validateFinalTransactionData enforces OID4VP 1.0 §5.1 and §8.4/§8.5 for the
// Final path: every credential_ids member must name a dc+sd-jwt query that
// requires holder binding, the only query whose presentation can carry the
// hashes (§8.4, Appendix B.3.3).
func (b *requestBuilder) validateFinalTransactionData() error {
	queries := make(map[string]CredentialQuery)
	if b.req.DcqlQuery != nil {
		for _, query := range b.req.DcqlQuery.Credentials {
			queries[query.ID] = query
		}
	}
	alg, err := validateTransactionData(b.req.TransactionData, b.settings().supportedTransactionDataTypes, func(i int, id string) error {
		query, known := queries[id]
		if !known {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].credential_ids references an unknown credential query", i)
		}
		if query.Format != "dc+sd-jwt" {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].credential_ids references a %s credential query, which cannot carry transaction data", i, query.Format)
		}
		if !query.RequiresHolderBinding() {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].credential_ids references a credential query without cryptographic holder binding", i)
		}
		return nil
	})
	if err != nil {
		return err
	}
	b.req.TransactionDataHashesAlg = alg
	return nil
}

// validateTransactionData checks every transaction_data entry: base64url JSON
// with a supported type and a non-empty credential_ids array whose members
// checkCredential accepts. It returns the transaction_data_hashes_alg the
// entries agree on. Any failure is invalid_transaction_data.
func validateTransactionData(entries []string, supportedTypes []string, checkCredential func(index int, id string) error) (string, error) {
	resolvedAlg := ""
	for i, encoded := range entries {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d] is not base64url-encoded JSON: %v", i, err)
		}
		var entry map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&entry); err != nil {
			return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d] is not a JSON object: %v", i, err)
		}
		dataType, ok := entry["type"].(string)
		if !ok || dataType == "" {
			return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].type is required and must be a string", i)
		}
		if !slices.Contains(supportedTypes, dataType) {
			return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].type %q: %w", i, dataType, ErrTransactionDataTypeUnsupported)
		}
		credentialIDs, ok := entry["credential_ids"].([]any)
		if !ok || len(credentialIDs) == 0 {
			return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].credential_ids must be a non-empty array", i)
		}
		for _, rawID := range credentialIDs {
			id, ok := rawID.(string)
			if !ok {
				return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].credential_ids must contain strings", i)
			}
			if err := checkCredential(i, id); err != nil {
				return "", err
			}
		}
		// transaction_data_hashes_alg sits in the transaction_data object
		// (OID4VP 1.0 Appendix B.3.3.1, Draft 24 Section 5.1). The Wallet
		// picks the first algorithm it supports, defaulting to sha-256.
		entryAlg, err := selectTransactionDataHashesAlg(i, entry)
		if err != nil {
			return "", err
		}
		if resolvedAlg == "" {
			resolvedAlg = entryAlg
		} else if resolvedAlg != entryAlg {
			return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data objects request conflicting transaction_data_hashes_alg values")
		}
	}
	return resolvedAlg, nil
}

// selectTransactionDataHashesAlg returns the first hash algorithm supported by
// this wallet from one transaction_data object's transaction_data_hashes_alg
// array, or sha-256 when the array is absent (OID4VP 1.0 Appendix B.3.3.1).
func selectTransactionDataHashesAlg(index int, entry map[string]any) (string, error) {
	rawAlg, exists := entry["transaction_data_hashes_alg"]
	if !exists || rawAlg == nil {
		return "sha-256", nil
	}
	algs, ok := rawAlg.([]any)
	if !ok || len(algs) == 0 {
		return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].transaction_data_hashes_alg must be a non-empty array of strings", index)
	}
	for _, rawName := range algs {
		name, ok := rawName.(string)
		if !ok || name == "" {
			return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].transaction_data_hashes_alg must contain only non-empty strings", index)
		}
		switch strings.ToLower(name) {
		case "sha-256", "sha-384", "sha-512":
			return strings.ToLower(name), nil
		}
	}
	return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].transaction_data_hashes_alg has no supported hash algorithm", index)
}
