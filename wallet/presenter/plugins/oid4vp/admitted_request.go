package oid4vp

import (
	"bytes"
	"maps"
	"net/url"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// ErrRequestNotAdmittedHere reports a request handle this presenter did not
// admit: another plugin instance parsed it, or it is not an *AdmittedRequest.
// The trust policy that admitted a request is the one that answers it.
var ErrRequestNotAdmittedHere = common.NewCodedError("request_not_admitted_here", "the request was not admitted by this presenter")

// ErrResponseTypeMismatch reports a response the admitted request does not
// take: a DCQL response to a Draft 24 request, or a Presentation Exchange
// response to an OpenID4VP 1.0 request.
var ErrResponseTypeMismatch = common.NewCodedError("presentation_response_type_mismatch", "the response does not match the admitted request's protocol version")

// AdmittedRequest is an Authorization Request this presenter parsed and
// admitted under its trust policy. Only the presenter that admitted it
// answers it, at the response endpoint the request named. It is built only by
// the parse methods of Oid4vpPresenter and is not serializable; a caller that
// presents later keeps RequestObject and parses it again.
type AdmittedRequest struct {
	req           *CredentialPresentationRequest
	endpoint      *url.URL
	wire          wireContract
	dcapiOrigin   string
	requestObject string
	admittedBy    *Oid4vpPresenter
}

var _ types.AdmittedRequest = (*AdmittedRequest)(nil)

// wireContract is the OpenID4VP version a request was admitted under.
type wireContract int

const (
	wireOpenID4VP1 wireContract = iota
	wireDraft24
)

// Protocol reports types.Oid4vp.
func (r *AdmittedRequest) Protocol() types.SupportedPresentationProtocol {
	return types.Oid4vp
}

// Request returns a deep copy of the admitted request; changing it changes
// nothing about the request this handle answers.
func (r *AdmittedRequest) Request() CredentialPresentationRequest {
	if r == nil || r.req == nil {
		return CredentialPresentationRequest{}
	}
	return cloneCredentialPresentationRequest(r.req)
}

// ResponseEndpoint returns a copy of the endpoint the response goes to:
// response_uri under direct_post and direct_post.jwt, redirect_uri otherwise.
// It is nil for a Digital Credentials API request.
func (r *AdmittedRequest) ResponseEndpoint() *url.URL {
	if r == nil || r.endpoint == nil {
		return nil
	}
	endpoint := *r.endpoint
	if r.endpoint.User != nil {
		user := *r.endpoint.User
		endpoint.User = &user
	}
	return &endpoint
}

// RequestObject returns the Request Object the request was authenticated
// from, or "" for a request in plain parameters.
func (r *AdmittedRequest) RequestObject() string {
	if r == nil {
		return ""
	}
	return r.requestObject
}

// Draft24 reports whether the request was admitted over the OpenID4VP Draft
// 24 wire contract.
func (r *AdmittedRequest) Draft24() bool {
	return r != nil && r.wire == wireDraft24
}

// isDCAPI reports whether the request arrived through the DC API.
func (r *AdmittedRequest) isDCAPI() bool {
	return r.dcapiOrigin != ""
}

// admit wraps an admitted request in the handle only p can answer.
func (p *Oid4vpPresenter) admit(req *CredentialPresentationRequest, wire wireContract, requestObject string) (*AdmittedRequest, error) {
	handle := &AdmittedRequest{req: req, wire: wire, requestObject: requestObject, admittedBy: p}
	if req.DCAPIProtocol != "" {
		handle.dcapiOrigin = req.ResponseAudience
		return handle, nil
	}
	endpoint, err := url.Parse(req.responseEndpoint())
	if err != nil || req.responseEndpoint() == "" {
		return nil, newAuthorizationRequestError(InvalidRequestError, "the request names no usable response endpoint")
	}
	handle.endpoint = endpoint
	return handle, nil
}

// admittedHere returns req as a handle p admitted.
func (p *Oid4vpPresenter) admittedHere(req types.AdmittedRequest) (*AdmittedRequest, error) {
	handle, ok := req.(*AdmittedRequest)
	if p == nil || !ok || handle == nil || handle.req == nil || handle.admittedBy != p {
		return nil, ErrRequestNotAdmittedHere
	}
	return handle, nil
}

// asAdmitted converts a parse result to the interface without producing a
// typed nil, and codes an uncoded refusal (codeParseError).
func asAdmitted(handle *AdmittedRequest, err error) (types.AdmittedRequest, error) {
	if err != nil {
		return nil, codeParseError(err)
	}
	return handle, nil
}

// cloneCredentialPresentationRequest deep-copies a request so a caller cannot
// reach the handle's own values.
func cloneCredentialPresentationRequest(src *CredentialPresentationRequest) CredentialPresentationRequest {
	dst := *src
	if src.OAuthAuthzRequest != nil {
		oauth := *src.OAuthAuthzRequest
		dst.OAuthAuthzRequest = &oauth
	}
	dst.RequestObjectVerification = cloneRequestObjectVerification(src.RequestObjectVerification)
	dst.VerifierFederation = cloneFederationEvidence(src.VerifierFederation)
	if src.PresentationDefinition != nil {
		definition := *src.PresentationDefinition
		dst.PresentationDefinition = &definition
	}
	dst.RawPresentationDefinition = bytes.Clone(src.RawPresentationDefinition)
	dst.DcqlQuery = cloneDcqlQuery(src.DcqlQuery)
	dst.ClientMetadata = cloneVerifierMetadata(src.ClientMetadata)
	dst.TransactionData = slices.Clone(src.TransactionData)
	if src.VerifierInfo != nil {
		dst.VerifierInfo = cloneJSONValue(src.VerifierInfo).([]any)
	}
	return dst
}

func cloneRequestObjectVerification(src *RequestObjectVerification) *RequestObjectVerification {
	if src == nil {
		return nil
	}
	dst := *src
	dst.CertificateSHA256 = slices.Clone(src.CertificateSHA256)
	if src.Certificate != nil {
		certificate := *src.Certificate
		certificate.DNSNames = slices.Clone(src.Certificate.DNSNames)
		dst.Certificate = &certificate
	}
	if src.VerifierAttestation != nil {
		attestation := *src.VerifierAttestation
		attestation.RedirectURIs = slices.Clone(src.VerifierAttestation.RedirectURIs)
		dst.VerifierAttestation = &attestation
	}
	dst.Federation = cloneFederationEvidence(src.Federation)
	return &dst
}

func cloneFederationEvidence(src *FederationEvidence) *FederationEvidence {
	if src == nil {
		return nil
	}
	dst := *src
	dst.TrustPathEntityIDs = slices.Clone(src.TrustPathEntityIDs)
	if src.Metadata != nil {
		dst.Metadata = cloneJSONValue(src.Metadata).(map[string]any)
	}
	return &dst
}

func cloneDcqlQuery(src *DcqlQuery) *DcqlQuery {
	if src == nil {
		return nil
	}
	dst := &DcqlQuery{}
	if src.Credentials != nil {
		dst.Credentials = make([]CredentialQuery, len(src.Credentials))
		for i, query := range src.Credentials {
			copied := query
			if query.Meta != nil {
				copied.Meta = cloneJSONValue(query.Meta).(map[string]any)
			}
			if query.Claims != nil {
				copied.Claims = make([]DCQLClaimQuery, len(query.Claims))
				for j, claim := range query.Claims {
					copied.Claims[j] = DCQLClaimQuery{
						ID:     claim.ID,
						Path:   cloneAnySlice(claim.Path),
						Values: cloneAnySlice(claim.Values),
					}
				}
			}
			copied.ClaimSets = cloneStringMatrix(query.ClaimSets)
			if query.TrustedAuthorities != nil {
				copied.TrustedAuthorities = make([]TrustedAuthority, len(query.TrustedAuthorities))
				for j, authority := range query.TrustedAuthorities {
					copied.TrustedAuthorities[j] = TrustedAuthority{Type: authority.Type, Values: slices.Clone(authority.Values)}
				}
			}
			if query.RequireCryptographicHolderBinding != nil {
				required := *query.RequireCryptographicHolderBinding
				copied.RequireCryptographicHolderBinding = &required
			}
			dst.Credentials[i] = copied
		}
	}
	if src.CredentialSets != nil {
		dst.CredentialSets = make([]CredentialSetQuery, len(src.CredentialSets))
		for i, set := range src.CredentialSets {
			copied := CredentialSetQuery{Options: cloneStringMatrix(set.Options)}
			if set.Required != nil {
				required := *set.Required
				copied.Required = &required
			}
			dst.CredentialSets[i] = copied
		}
	}
	return dst
}

func cloneVerifierMetadata(src *VerifierMetadata) *VerifierMetadata {
	if src == nil {
		return nil
	}
	dst := *src
	dst.RedirectURIs = slices.Clone(src.RedirectURIs)
	dst.GrantTypes = slices.Clone(src.GrantTypes)
	dst.ResponseTypes = slices.Clone(src.ResponseTypes)
	dst.Contacts = slices.Clone(src.Contacts)
	dst.EncryptedResponseEncValuesSupported = slices.Clone(src.EncryptedResponseEncValuesSupported)
	// A JSONWebKey's key material is immutable; copying the entries is enough.
	dst.Jwks = jose.JSONWebKeySet{Keys: slices.Clone(src.Jwks.Keys)}
	return &dst
}

func cloneStringMatrix(src [][]string) [][]string {
	if src == nil {
		return nil
	}
	dst := make([][]string, len(src))
	for i, row := range src {
		dst[i] = slices.Clone(row)
	}
	return dst
}

func cloneAnySlice(src []any) []any {
	if src == nil {
		return nil
	}
	return cloneJSONValue(src).([]any)
}

// cloneJSONValue deep-copies a decoded JSON value.
func cloneJSONValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		copied := maps.Clone(v)
		for key, item := range copied {
			copied[key] = cloneJSONValue(item)
		}
		return copied
	case []any:
		copied := slices.Clone(v)
		for i, item := range copied {
			copied[i] = cloneJSONValue(item)
		}
		return copied
	case []string:
		return slices.Clone(v)
	default:
		return v
	}
}
