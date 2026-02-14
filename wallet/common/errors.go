package common

import (
	"errors"
	"fmt"
)

// Common error types that can be used across all components
var (
	ErrNotImplemented = errors.New("not implemented")
	ErrInvalidInput   = errors.New("invalid input")
	ErrInternalError  = errors.New("internal error")
	ErrTimeout        = errors.New("operation timeout")
	ErrCancelled      = errors.New("operation cancelled")
)

// ComponentError represents a generic error for any component
type ComponentError struct {
	Component string `json:"component"`
	Op        string `json:"operation"`
	Err       error  `json:"error"`
}

func (e *ComponentError) Error() string {
	return fmt.Sprintf("%s component operation %s: %v", e.Component, e.Op, e.Err)
}

func (e *ComponentError) Unwrap() error {
	return e.Err
}

// NewComponentError creates a new ComponentError
func NewComponentError(component, op string, err error) *ComponentError {
	return &ComponentError{
		Component: component,
		Op:        op,
		Err:       err,
	}
}

// WrapError wraps an error with additional context
func WrapError(err error, context string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", context, err)
}

// IsErrorType checks if an error is of a specific type using errors.Is
func IsErrorType(err, target error) bool {
	return errors.Is(err, target)
}

// GetRootCause returns the root cause of an error by unwrapping
func GetRootCause(err error) error {
	for {
		if unwrapper, ok := err.(interface{ Unwrap() error }); ok {
			underlying := unwrapper.Unwrap()
			if underlying == nil {
				break
			}
			err = underlying
		} else {
			break
		}
	}
	return err
}
