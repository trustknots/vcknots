package sdjwtvc

import (
	"errors"

	"github.com/trustknots/vcknots/wallet/internal/credential"
	"github.com/trustknots/vcknots/wallet/internal/serializer/types"
)

type SdJwtVcSerializer struct{}

func NewSdJwtVcSerializer() *SdJwtVcSerializer {
	return &SdJwtVcSerializer{}
}

// SerializeCredential serializes a credential to JWT VC format
func (s *SdJwtVcSerializer) SerializeCredential(flavor credential.SupportedSerializationFlavor, cred *credential.Credential) ([]byte, error) {
	if flavor != credential.SDJwtVC {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected JWT VC format")
	}

	// This method is not fully implemented in the original Dart code
	return nil, types.NewFormatError(flavor, errors.New("not implemented"), "SerializeCredential not implemented for SD JWT VC format")
}

// DeserializeCredential deserializes a JWT VC formatted credential
func (s *SdJwtVcSerializer) DeserializeCredential(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.Credential, error) {
	if flavor != credential.SDJwtVC {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected JWT VC format")
	}

	// This method is not fully implemented in the original Dart code
	return nil, types.NewFormatError(flavor, errors.New("not implemented"), "DeserializeCredential not implemented for SD JWT VC format")
}

// SerializePresentation serializes a credential presentation to JWT VC format
func (s *SdJwtVcSerializer) SerializePresentation(flavor credential.SupportedSerializationFlavor, presentation *credential.CredentialPresentation, key interface{}) ([]byte, *credential.CredentialPresentation, error) {
	if flavor != credential.SDJwtVC {
		return nil, nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected JWT VC format")
	}

	// This method is not fully implemented in the original Dart code
	return nil, nil, types.NewFormatError(flavor, errors.New("not implemented"), "SerializePresentation not implemented for SD JWT VC format")
}

// DeserializePresentation deserializes a JWT VC formatted credential presentation
func (s *SdJwtVcSerializer) DeserializePresentation(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.CredentialPresentation, error) {
	if flavor != credential.SDJwtVC {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected JWT VC format")
	}

	// This method is not fully implemented in the original Dart code
	return nil, types.NewFormatError(flavor, errors.New("not implemented"), "DeserializePresentation not implemented for SD JWT VC format")
}
