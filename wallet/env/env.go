package env

import (
	"os"
	"strings"
)


type EnvKey int

const _PREFIX = "VCKNOTS_WALLET_"

const (
	DEBUG EnvKey = iota
	HTTP_ALLOWED
	envKeyCount
)

func (k EnvKey) String() string {
	var postfix string
	switch k {
	case DEBUG:
		postfix = "DEBUG"
	case HTTP_ALLOWED:
		postfix = "HTTP_ALLOWED"
	}
	return _PREFIX + postfix
}


func GetEnv(key EnvKey) string {
	keyStr := key.String()
	return os.Getenv(keyStr)
}


func SetDebugMode(value bool) {
	if value {
		os.Setenv(DEBUG.String(), "true")
	} else {
		os.Setenv(DEBUG.String(), "")
	}
}

func IsDebugMode() bool {
	return strings.EqualFold(GetEnv(DEBUG), "true")
}


func SetHTTPAllowed(value bool) {
	if value {
		os.Setenv(HTTP_ALLOWED.String(), "true")
	} else {
		os.Setenv(HTTP_ALLOWED.String(), "")
	}
}

func IsHTTPAllowed() bool {
	if strings.EqualFold(GetEnv(HTTP_ALLOWED), "true") || IsDebugMode() {
		return true
	}
	return false
}
