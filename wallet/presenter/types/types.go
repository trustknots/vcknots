// Package types defines the presenter plugin interface, presentation request
// parameters and errors.
package types

import (
	"fmt"
	"net/url"

	"github.com/trustknots/vcknots/wallet/common"
)

// Sentinel errors for presentation operations
var (
	ErrUnsupportedProtocol  = common.NewCodedError("presenter_unsupported_protocol", "unsupported presentation protocol")
	ErrInvalidEndpoint      = common.NewCodedError("presenter_invalid_endpoint", "invalid presentation endpoint")
	ErrInvalidPresentation  = common.NewCodedError("presenter_invalid_presentation", "invalid presentation data")
	ErrPresentationFailed   = common.NewCodedError("presenter_presentation_failed", "presentation submission failed")
	ErrNetworkFailed        = common.NewCodedError("presenter_network_failed", "network request failed")
	ErrInvalidResponse      = common.NewCodedError("presenter_invalid_response", "invalid response from verifier")
	ErrTimeoutExpired       = common.NewCodedError("presenter_timeout_expired", "presentation request timeout expired")
	ErrAuthenticationFailed = common.NewCodedError("presenter_authentication_failed", "authentication failed")
	ErrPluginNotFound       = common.NewCodedError("presenter_plugin_not_found", "presenter plugin not found")
	ErrNilPlugin            = common.NewCodedError("presenter_nil_plugin", "presenter plugin cannot be nil")
)

// PresenterError represents an error during presentation operations
type PresenterError struct {
	Protocol SupportedPresentationProtocol `json:"protocol"`
	Endpoint string                        `json:"endpoint,omitempty"`
	Op       string                        `json:"operation"`
	Err      error                         `json:"error"`
}

// Error implements error.
func (e *PresenterError) Error() string {
	if e.Endpoint != "" {
		return fmt.Sprintf("presenter %v operation %s at %s: %v", e.Protocol, e.Op, e.Endpoint, e.Err)
	}
	return fmt.Sprintf("presenter %v operation %s: %v", e.Protocol, e.Op, e.Err)
}

// Unwrap returns the wrapped error.
func (e *PresenterError) Unwrap() error {
	return e.Err
}

// NewPresenterError creates a new PresenterError
func NewPresenterError(protocol SupportedPresentationProtocol, endpoint, op string, err error) *PresenterError {
	return &PresenterError{
		Protocol: protocol,
		Endpoint: endpoint,
		Op:       op,
		Err:      err,
	}
}

// PresentationRequest contains the information needed to present a credential
type PresentationRequest struct {
	State string
	// ResponseMode is the Authorization Request response_mode. For the Final
	// DCQL path "direct_post.jwt" requires an encrypted response and
	// "direct_post" a plaintext one; an empty value lets the presenter infer the
	// mode from the verifier's encryption metadata.
	ResponseMode string
	// CredentialQueryID is the id of the DCQL Credential Query the presentation
	// responds to. It becomes the key of the vp_token JSON object.
	CredentialQueryID             string
	ClientMetadata                interface{}
	AuthorizationEncryptedRespAlg string
	AuthorizationEncryptedRespEnc string
}

// Presenter sends a serialized presentation to a verifier endpoint and returns
// the redirect URI from the verifier's response, if any.
type Presenter interface {
	Present(protocol SupportedPresentationProtocol, endpoint url.URL, serializedPresentation []byte, request *PresentationRequest) (string, error)
}

// SupportedPresentationProtocol identifies a presentation protocol.
type SupportedPresentationProtocol int

const (
	// Oid4vp is OpenID for Verifiable Presentations.
	Oid4vp SupportedPresentationProtocol = iota
)

// PresentationSubmission and DescriptorMapItem are used by the explicit Draft24 API.
type PresentationSubmission struct {
	ID            string              `json:"id"`
	DefinitionID  string              `json:"definition_id"`
	DescriptorMap []DescriptorMapItem `json:"descriptor_map"`
}

// DescriptorMapItem is one descriptor_map entry of a PresentationSubmission.
type DescriptorMapItem struct {
	ID         string             `json:"id"`
	Format     string             `json:"format"`
	Path       string             `json:"path"`
	PathNested *DescriptorMapItem `json:"path_nested,omitempty"`
}
