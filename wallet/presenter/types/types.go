package types

import (
	"errors"
	"fmt"
	"net/url"
)

// Sentinel errors for presentation operations
var (
	ErrUnsupportedProtocol  = errors.New("unsupported presentation protocol")
	ErrInvalidEndpoint      = errors.New("invalid presentation endpoint")
	ErrInvalidPresentation  = errors.New("invalid presentation data")
	ErrInvalidSubmission    = errors.New("invalid presentation submission")
	ErrPresentationFailed   = errors.New("presentation submission failed")
	ErrNetworkFailed        = errors.New("network request failed")
	ErrInvalidResponse      = errors.New("invalid response from verifier")
	ErrTimeoutExpired       = errors.New("presentation request timeout expired")
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrInvalidDescriptorMap = errors.New("invalid descriptor map")
	ErrPluginNotFound       = errors.New("presenter plugin not found")
	ErrNilPlugin            = errors.New("presenter plugin cannot be nil")
)

// PresenterError represents an error during presentation operations
type PresenterError struct {
	Protocol SupportedPresentationProtocol `json:"protocol"`
	Endpoint string                        `json:"endpoint,omitempty"`
	Op       string                        `json:"operation"`
	Err      error                         `json:"error"`
}

func (e *PresenterError) Error() string {
	if e.Endpoint != "" {
		return fmt.Sprintf("presenter %v operation %s at %s: %v", e.Protocol, e.Op, e.Endpoint, e.Err)
	}
	return fmt.Sprintf("presenter %v operation %s: %v", e.Protocol, e.Op, e.Err)
}

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

type Presenter interface {
	Present(protocol SupportedPresentationProtocol, endpoint url.URL, serializedPresentation []byte, presentationSubmission PresentationSubmission) error
}

type SupportedPresentationProtocol int

const (
	Oid4vp SupportedPresentationProtocol = iota
)

type PresentationSubmission struct {
	ID            string              `json:"id"`
	DefinitionID  string              `json:"definition_id"`
	DescriptorMap []DescriptorMapItem `json:"descriptor_map"`
}

type DescriptorMapItem struct {
	ID         string             `json:"id"`
	Format     string             `json:"format"`
	Path       string             `json:"path"`
	PathNested *DescriptorMapItem `json:"path_nested,omitempty"`
}
