// Package oid4vci implements the OpenID for Verifiable Credential Issuance
// receiver plugin, which performs the HTTP exchanges with a Credential Issuer
// and its authorization server.
package oid4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// Oid4vciReceiver is the bundled OpenID4VCI receiver plugin. It implements
// the upstream types.Receiver, types.OID4VCITransport for OpenID4VCI 1.0 and
// HAIP 1.0, and types.Draft13Transport. It performs HTTP only; every signed
// value reaches it through a factory.
//
// Fields must not change once the receiver is registered. A zero
// Oid4vciReceiver is usable and must not be copied after first use.
type Oid4vciReceiver struct {
	// HTTPClient sends every request; nil means a bounded default client.
	// Redirects are never followed.
	HTTPClient *http.Client
	// AllowHTTP permits HTTP endpoints for a local test issuer. The zero value requires HTTPS.
	AllowHTTP bool
	// AppendedMetadataPathFallback retries Credential Issuer Metadata at the
	// OpenID4VCI Draft 13 Section 11.2.2 location, the well-known path appended
	// to an identifier that has a path, when the Section 12.2.2 location
	// answers 404. It is off by default and never applies under HAIP.
	AppendedMetadataPathFallback bool
	// Profile selects the OpenID4VCI 1.0 policy. The zero value normalizes to
	// profile.Final; profile.HAIP enforces HAIP 1.0.
	Profile profile.Profile
	// IssuerMetadataSigning configures OpenID4VCI 1.0 Section 12.2.3 signed
	// Credential Issuer Metadata. A nil value requests signed metadata under
	// HAIP and accepts an unsigned application/json document in every profile;
	// see IssuerMetadataSigningOptions for the defaults each field takes.
	IssuerMetadataSigning *IssuerMetadataSigningOptions
	// IssuerMetadataFederation resolves the Credential Issuer Metadata of an
	// issuer whose metadata document is not found (404) from its OpenID
	// Federation Entity: the openid_credential_issuer metadata derived from a
	// Trust Chain to one of the resolver's TrustAnchors (OpenID Federation 1.0
	// Section 6.1.4). A nil HTTPClient uses HTTPClient. Without a valid chain
	// the fetch fails. It does not apply when IssuerMetadataSigning.Require is
	// set, because the result is not Section 12.2.3 signed metadata.
	IssuerMetadataFederation *federation.Resolver

	// dpopNonceMu guards dpopNonces.
	dpopNonceMu sync.Mutex
	// dpopNonces is created on first use and kept behind a pointer so that
	// Oid4vciReceiver stays comparable.
	dpopNonces *dpopNonceCache
}

var (
	_ types.Receiver         = (*Oid4vciReceiver)(nil)
	_ types.OID4VCITransport = (*Oid4vciReceiver)(nil)
	_ types.Draft13Transport = (*Oid4vciReceiver)(nil)
	_ types.HTTPSchemePolicy = (*Oid4vciReceiver)(nil)
	_ profile.Carrier        = (*Oid4vciReceiver)(nil)
)

// ProtocolProfile reports the normalized OID4VCI profile this receiver enforces.
func (o *Oid4vciReceiver) ProtocolProfile() profile.Profile {
	normalized, err := o.Profile.Normalize()
	if err != nil {
		return o.Profile
	}
	return normalized
}

// normalizedProfile normalizes the configured profile once. Unknown values fail
// closed before any network access so every checkpoint reads a validated value.
func (o *Oid4vciReceiver) normalizedProfile() (profile.Profile, error) {
	normalized, err := o.Profile.Normalize()
	if err != nil {
		return "", fmt.Errorf("invalid OID4VCI profile: %w", err)
	}
	return normalized, nil
}

// requireHAIPTransport rejects the test-only HTTP escape when HAIP is selected.
// HAIP §4 requires TLS for issuer and authorization server endpoints.
func (o *Oid4vciReceiver) requireHAIPTransport(normalized profile.Profile) error {
	if normalized.IsHAIP() && o.AllowHTTP {
		return fmt.Errorf("%w: HAIP profile does not permit AllowHTTP", common.ErrInvalidInput)
	}
	return nil
}

// ErrHTTPRedirectNotAllowed reports that an OpenID4VCI endpoint answered with
// a redirect. No OpenID4VCI endpoint is defined to redirect, and following one
// would replay the body and the Authorization, DPoP and client attestation
// headers to an origin the response chose.
var ErrHTTPRedirectNotAllowed = common.NewCodedError("http_redirect_not_allowed", "OID4VCI endpoint redirected; redirects are not followed")

// OID4VCICredentialFormatToSerializationFlavor maps OID4VCI credential format
// identifiers to wallet serialization flavors. SD-JWT VC is "dc+sd-jwt" in
// OpenID4VCI 1.0 Appendix A.3 and "vc+sd-jwt" in Draft 13 Appendix A.3.
func OID4VCICredentialFormatToSerializationFlavor(format string) (credential.SupportedSerializationFlavor, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "jwt_vc_json", "jwt_vc", string(credential.JwtVc):
		return credential.JwtVc, nil
	case "dc+sd-jwt", "vc+sd-jwt", string(credential.SDJwtVC):
		return credential.SDJwtVC, nil
	case "ldp_vc", string(credential.LdpVc):
		return credential.LdpVc, nil
	default:
		return "", fmt.Errorf("unsupported credential format: %q", format)
	}
}

// ReceiveCredential performs a Draft 13 credential request. It is a
// types.Receiver method and carries no context; it binds its request to
// context.Background().
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

	requestOptions := firstCredentialRequestOptions(options)
	var dpopProof string
	if strings.EqualFold(accessToken.TokenType, dpopAuthorizationScheme) {
		if requestOptions == nil || requestOptions.DPoPProofJWT == nil || *requestOptions.DPoPProofJWT == "" {
			return nil, fmt.Errorf("DPoP proof JWT is required for DPoP access token")
		}
		dpopProof = *requestOptions.DPoPProofJWT
	}
	response, err := o.do(observe.WithEndpoint(context.Background(), observe.EndpointCredential), exchange{
		method:      http.MethodPost,
		url:         endpointURL,
		contentType: "application/json; charset=utf-8",
		body:        func() ([]byte, error) { return reqBodyBytes, nil },
		header: func(header http.Header) error {
			if dpopProof != "" {
				header.Set("DPoP", dpopProof)
			}
			return nil
		},
		accessToken: &accessToken,
		limit:       httpfetch.CredentialBodyLimit,
	})
	if err != nil {
		return nil, err
	}
	bodyBytes := response.body
	if response.statusCode != http.StatusOK {
		if isUseDPoPNonce(response) {
			return nil, fmt.Errorf(
				"%w; status: %d; endpoint: %s",
				types.NewDPoPNonceError(response.header.Get("DPoP-Nonce"), types.ErrUseDPoPNonce),
				response.statusCode,
				endpointURL.String(),
			)
		}
		return nil, fmt.Errorf("failed to receive credential from %s: %w", endpointURL.String(), response.statusError())
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
