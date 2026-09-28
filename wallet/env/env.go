// Package env reads the VCKNOTS_WALLET_* environment variables that configure
// the wallet.
package env

import (
	"os"
	"strings"
)

// EnvKey identifies a VCKNOTS_WALLET_* environment variable.
type EnvKey int

const _PREFIX = "VCKNOTS_WALLET_"

const (
	// DEBUG selects the VCKNOTS_WALLET_DEBUG environment variable.
	DEBUG EnvKey = iota
	envKeyCount
)

// String returns the full environment variable name for k.
func (k EnvKey) String() string {
	var postfix string
	switch k {
	case DEBUG:
		postfix = "DEBUG"
	}
	return _PREFIX + postfix
}

// GetEnv returns the current value of the environment variable identified by key.
func GetEnv(key EnvKey) string {
	keyStr := key.String()
	return os.Getenv(keyStr)
}

// SetDebugMode enables or disables debug mode.
func SetDebugMode(value bool) {
	if value {
		os.Setenv(DEBUG.String(), "true")
	} else {
		os.Setenv(DEBUG.String(), "")
	}
}

// IsDebugMode reports whether debug mode is enabled.
func IsDebugMode() bool {
	return strings.EqualFold(GetEnv(DEBUG), "true")
}
