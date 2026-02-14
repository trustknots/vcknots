package common

import (
	"errors"
	"testing"
)

func TestNewComponentError(t *testing.T) {
	component := "testComponent"
	op := "testOperation"
	origErr := errors.New("original error")

	err := NewComponentError(component, op, origErr)

	if err.Component != component {
		t.Errorf("ComponentError.Component = %v, want %v", err.Component, component)
	}
	if err.Op != op {
		t.Errorf("ComponentError.Op = %v, want %v", err.Op, op)
	}
	if err.Err != origErr {
		t.Errorf("ComponentError.Err = %v, want %v", err.Err, origErr)
	}
}

func TestComponentError_Error(t *testing.T) {
	component := "testComponent"
	op := "testOperation"
	origErr := errors.New("original error")

	err := NewComponentError(component, op, origErr)
	errorMsg := err.Error()

	// Verify that the error message contains the component name, operation name, and the original error
	expectedSubstrings := []string{component, op, origErr.Error()}
	for _, substr := range expectedSubstrings {
		if !contains(errorMsg, substr) {
			t.Errorf("ComponentError.Error() = %v, should contain %v", errorMsg, substr)
		}
	}
}

func TestComponentError_Unwrap(t *testing.T) {
	origErr := errors.New("original error")
	err := NewComponentError("component", "operation", origErr)

	unwrapped := err.Unwrap()
	if unwrapped != origErr {
		t.Errorf("ComponentError.Unwrap() = %v, want %v", unwrapped, origErr)
	}
}

func TestWrapError(t *testing.T) {
	origErr := errors.New("original error")
	context := "test context"

	wrappedErr := WrapError(origErr, context)

	if wrappedErr == nil {
		t.Error("WrapError() returned nil")
		return
	}

	// Verify that the error message contains the context and the original error
	errorMsg := wrappedErr.Error()
	if !contains(errorMsg, context) {
		t.Errorf("WrapError() error message should contain context: %v", errorMsg)
	}
	if !contains(errorMsg, origErr.Error()) {
		t.Errorf("WrapError() error message should contain original error: %v", errorMsg)
	}

	// Confirm that the original error can be retrieved using errors.Unwrap
	if !errors.Is(wrappedErr, origErr) {
		t.Error("WrapError() should wrap the original error")
	}
}

func TestWrapError_WithNilError(t *testing.T) {
	result := WrapError(nil, "context")
	if result != nil {
		t.Errorf("WrapError(nil, context) = %v, want nil", result)
	}
}

func TestIsErrorType(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		target   error
		expected bool
	}{
		{
			name:     "direct match",
			err:      ErrNotImplemented,
			target:   ErrNotImplemented,
			expected: true,
		},
		{
			name:     "wrapped error match",
			err:      NewComponentError("comp", "op", ErrInvalidInput),
			target:   ErrInvalidInput,
			expected: true,
		},
		{
			name:     "no match",
			err:      ErrNotImplemented,
			target:   ErrInvalidInput,
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			target:   ErrNotImplemented,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsErrorType(tt.err, tt.target)
			if result != tt.expected {
				t.Errorf("IsErrorType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetRootCause(t *testing.T) {
	origErr := errors.New("root cause")
	wrappedOnce := NewComponentError("comp1", "op1", origErr)
	wrappedTwice := NewComponentError("comp2", "op2", wrappedOnce)

	tests := []struct {
		name     string
		err      error
		expected error
	}{
		{
			name:     "no wrapping",
			err:      origErr,
			expected: origErr,
		},
		{
			name:     "single wrap",
			err:      wrappedOnce,
			expected: origErr,
		},
		{
			name:     "double wrap",
			err:      wrappedTwice,
			expected: origErr,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetRootCause(tt.err)
			if result != tt.expected {
				t.Errorf("GetRootCause() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPredefinedErrors(t *testing.T) {
	// Verifying the existence of predefined error variables
	predefinedErrors := []error{
		ErrNotImplemented,
		ErrInvalidInput,
		ErrInternalError,
		ErrTimeout,
		ErrCancelled,
	}

	for i, err := range predefinedErrors {
		if err == nil {
			t.Errorf("predefined error %d is nil", i)
		}
		if err.Error() == "" {
			t.Errorf("predefined error %d has empty message", i)
		}
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && someContains(s, substr)))
}

func someContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
