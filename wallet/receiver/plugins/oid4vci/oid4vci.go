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
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
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
	// Experimental relaxes transport security for a local test issuer
	// (experimental.Transport.AllowHTTP). Not specification-conforming; for
	// testing only. The zero value requires HTTPS, as OpenID4VCI 1.0 Section
	// 12.2 does, and a profile with ForbidExperimental refuses any
	// other value.
	Experimental experimental.Transport
	// Profile is the OpenID4VCI 1.0 profile whose Options the receiver
	// applies. The zero value is profile.Final(); profile.HAIP() enforces
	// HAIP 1.0. A draft profile is refused (profile.ErrDraftProfile).
	Profile profile.Profile
	// IssuerMetadataSigning configures OpenID4VCI 1.0 Section 12.2.3 signed
	// Credential Issuer Metadata. A nil value requests signed metadata under
	// HAIP and accepts an unsigned application/json document in every profile;
	// see IssuerMetadataSigningOptions for the defaults each field takes.
	IssuerMetadataSigning *IssuerMetadataSigningOptions

	// dpopNonceMu guards dpopNonces and attestationChallenges.
	dpopNonceMu sync.Mutex
	// dpopNonces and attestationChallenges are created on first use and kept
	// behind pointers so that Oid4vciReceiver stays comparable.
	dpopNonces            *recentValues[dpopNonceKey]
	attestationChallenges *recentValues[attestationChallengeKey]
}

var (
	_ types.Receiver         = (*Oid4vciReceiver)(nil)
	_ types.OID4VCITransport = (*Oid4vciReceiver)(nil)
	_ types.Draft13Transport = (*Oid4vciReceiver)(nil)
	_ types.HTTPSchemePolicy = (*Oid4vciReceiver)(nil)
	_ profile.Carrier        = (*Oid4vciReceiver)(nil)
)

// ProtocolProfile reports the OpenID4VCI 1.0 profile this receiver enforces.
func (o *Oid4vciReceiver) ProtocolProfile() profile.Profile {
	return o.Profile
}

// profileOptions returns the Options of the configured profile. A draft
// profile fails closed before any network access.
func (o *Oid4vciReceiver) profileOptions() (profile.Options, error) {
	if err := o.Profile.RequireFinalVersion(); err != nil {
		return profile.Options{}, fmt.Errorf("invalid OID4VCI profile: %w", err)
	}
	return o.Profile.Options(), nil
}

// requireSecureTransport rejects the experimental HTTP escape under
// Options.ForbidExperimental (HAIP §4 requires TLS for issuer and
// authorization server endpoints). Every exchange applies it (do), so a
// receiver built with a HAIP profile and an experimental transport sends
// nothing, whether or not the wallet constructed it.
func (o *Oid4vciReceiver) requireSecureTransport(options profile.Options) error {
	if options.ForbidExperimental && o.Experimental != (experimental.Transport{}) {
		return fmt.Errorf("%w: %w does not permit Experimental.Transport", common.ErrInvalidInput, profile.Refused("ForbidExperimental"))
	}
	return nil
}

// ValidateProfile reports whether the receiver's own settings satisfy its
// profile: a draft profile is refused, and Options.ForbidExperimental
// refuses Experimental.Transport. The wallet calls it on an injected plugin
// before it accepts the plugin; every exchange applies the same rules.
func (o *Oid4vciReceiver) ValidateProfile() error {
	options, err := o.profileOptions()
	if err != nil {
		return err
	}
	return o.requireSecureTransport(options)
}

// ErrHTTPRedirectNotAllowed reports that an OpenID4VCI endpoint answered with
// a redirect. No OpenID4VCI endpoint is defined to redirect, and following one
// would replay the body and the Authorization, DPoP and client attestation
// headers to an origin the response chose.
var ErrHTTPRedirectNotAllowed = common.NewCodedError("http_redirect_not_allowed", "OID4VCI endpoint redirected; redirects are not followed")

// ReceiveCredential sends one OpenID4VCI 1.0 Credential Request (Section
// 8.2): credential_identifier when one is given, credential_configuration_id
// otherwise, and jwtProof as the only entry of proofs.jwt. credentialDefinition
// is not sent. It is the types.Receiver method; the wallet's issuance flows
// use OID4VCITransport and Draft13Transport instead. It carries no context and
// binds its request to context.Background().
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
