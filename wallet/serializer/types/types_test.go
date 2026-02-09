package types

import (
	"errors"
	"testing"

	"github.com/trustknots/vcknots/wallet/credential"
)

func TestSentinelErrors(t *testing.T) {
	// Test that our sentinel errors are properly defined
	testCases := []struct {
		name string
		err  error
	}{
		{"ErrUnsupportedFormat", ErrUnsupportedFormat},
		{"ErrInvalidJWT", ErrInvalidJWT},
		{"ErrInvalidCredential", ErrInvalidCredential},
		{"ErrInvalidPresentation", ErrInvalidPresentation},
		{"ErrMissingProof", ErrMissingProof},
		{"ErrSigningFailed", ErrSigningFailed},
		{"ErrDecodingFailed", ErrDecodingFailed},
		{"ErrUnsupportedAlgorithm", ErrUnsupportedAlgorithm},
		{"ErrPluginNotFound", ErrPluginNotFound},
		{"ErrNilPlugin", ErrNilPlugin},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				t.Errorf("%s should not be nil", tc.name)
			}
			if tc.err.Error() == "" {
				t.Errorf("%s should have a non-empty error message", tc.name)
			}
		})
	}
}

func TestNewFormatError(t *testing.T) {
	baseErr := errors.New("base error")
	err := NewFormatError(credential.JwtVc, baseErr, "test message")

	if err == nil {
		t.Fatal("NewFormatError should not return nil")
	}

	if !errors.Is(err, baseErr) {
		t.Error("NewFormatError should wrap the base error")
	}

	expectedMsg := "serialization format application/vc+jwt: test message: base error"
	if err.Error() != expectedMsg {
		t.Errorf("Expected %s, got %s", expectedMsg, err.Error())
	}
}

func TestNewInvalidJWTError(t *testing.T) {
	// Test without cause
	err := NewInvalidJWTError("test message", nil)
	if err == nil {
		t.Fatal("NewInvalidJWTError should not return nil")
	}

	if !errors.Is(err, ErrInvalidJWT) {
		t.Error("NewInvalidJWTError should wrap ErrInvalidJWT")
	}

	// Test with cause
	cause := errors.New("cause error")
	errWithCause := NewInvalidJWTError("test message", cause)

	if !errors.Is(errWithCause, ErrInvalidJWT) {
		t.Error("NewInvalidJWTError should wrap ErrInvalidJWT")
	}

	if !errors.Is(errWithCause, cause) {
		t.Error("NewInvalidJWTError should wrap the cause error")
	}
}

func TestNewInvalidCredentialError(t *testing.T) {
	// Test without cause
	err := NewInvalidCredentialError("test message", nil)
	if err == nil {
		t.Fatal("NewInvalidCredentialError should not return nil")
	}

	if !errors.Is(err, ErrInvalidCredential) {
		t.Error("NewInvalidCredentialError should wrap ErrInvalidCredential")
	}

	// Test with cause
	cause := errors.New("cause error")
	errWithCause := NewInvalidCredentialError("test message", cause)

	if !errors.Is(errWithCause, ErrInvalidCredential) {
		t.Error("NewInvalidCredentialError should wrap ErrInvalidCredential")
	}

	if !errors.Is(errWithCause, cause) {
		t.Error("NewInvalidCredentialError should wrap the cause error")
	}
}

func TestNewDecodingError(t *testing.T) {
	// Test without cause
	err := NewDecodingError("test message", nil)
	if err == nil {
		t.Fatal("NewDecodingError should not return nil")
	}

	if !errors.Is(err, ErrDecodingFailed) {
		t.Error("NewDecodingError should wrap ErrDecodingFailed")
	}

	// Test with cause
	cause := errors.New("cause error")
	errWithCause := NewDecodingError("test message", cause)

	if !errors.Is(errWithCause, ErrDecodingFailed) {
		t.Error("NewDecodingError should wrap ErrDecodingFailed")
	}

	if !errors.Is(errWithCause, cause) {
		t.Error("NewDecodingError should wrap the cause error")
	}
}

func TestErrorsIs(t *testing.T) {
	// Test that errors.Is works with our wrapped errors
	jwtErr := NewInvalidJWTError("invalid format", nil)

	if !errors.Is(jwtErr, ErrInvalidJWT) {
		t.Error("errors.Is should identify wrapped ErrInvalidJWT")
	}

	if errors.Is(jwtErr, ErrInvalidCredential) {
		t.Error("errors.Is should not match different error types")
	}
}
