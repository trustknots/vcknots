package env_test

import (
	"os"
	"strings"
	"testing"

	"github.com/trustknots/vcknots/wallet/env"
)

func TestSetDebugMode(t *testing.T) {
	t.Run("set and check", func(t *testing.T) {
		dbg_mode := env.IsDebugMode()
		defer env.SetDebugMode(dbg_mode)

		env.SetDebugMode(true)
		if result := os.Getenv(env.DEBUG.String()); !strings.EqualFold("true", result) {
			t.Fatalf("Set %v true, but result is \"%v\"", env.DEBUG.String(), result)
		}

		env.SetDebugMode(false)
		if result := os.Getenv(env.DEBUG.String()); !strings.EqualFold("", result) {
			t.Fatalf("Set %v empty, but result is \"%v\"", env.DEBUG.String(), result)
		}
	})
}

func TestSetHTTPAllowed(t *testing.T) {
	t.Run("set and check", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)

		env.SetHTTPAllowed(true)
		if result := os.Getenv(env.HTTP_ALLOWED.String()); !strings.EqualFold("true", result) {
			t.Fatalf("Set %v true, but result is \"%v\"", env.HTTP_ALLOWED.String(), result)
		}

		env.SetHTTPAllowed(false)
		if result := os.Getenv(env.HTTP_ALLOWED.String()); !strings.EqualFold("", result) {
			t.Fatalf("Set %v empty, but result is \"%v\"", env.HTTP_ALLOWED.String(), result)
		}
	})
}

func TestIsDebugMode(t *testing.T) {
	t.Run("check", func(t *testing.T) {
		dbg_mode := env.IsDebugMode()
		defer env.SetDebugMode(dbg_mode)

		os.Setenv(env.DEBUG.String(), "true")
		if result := env.IsDebugMode(); !result {
			t.Fatalf("Set debug mode on, but result is %v", result);
		}

		os.Setenv(env.DEBUG.String(), "false")
		if result := env.IsDebugMode(); result {
			t.Fatalf("Set debug mode on, but result is %v", result);
		}
	})
}

func TestIsHTTPAllowed(t *testing.T) {
	t.Run("check", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		dbg_mode := env.IsDebugMode()
		defer env.SetHTTPAllowed(http_allowed)
		defer env.SetDebugMode(dbg_mode)

		os.Setenv(env.DEBUG.String(), "")
		os.Setenv(env.HTTP_ALLOWED.String(), "")
		if result := env.IsHTTPAllowed(); result {
			t.Fatalf("Set HTTP allowed off, but result is %v", result)
		}

		os.Setenv(env.DEBUG.String(), "")
		os.Setenv(env.HTTP_ALLOWED.String(), "true")
		if result := env.IsHTTPAllowed(); !result {
			t.Fatalf("Set HTTP allowed on, but result is %v", result)
		}

		os.Setenv(env.DEBUG.String(), "true")
		os.Setenv(env.HTTP_ALLOWED.String(), "")
		if result := env.IsHTTPAllowed(); !result {
			t.Fatalf("Set debug mode on, but result is %v", result)
		}

		os.Setenv(env.DEBUG.String(), "true")
		os.Setenv(env.HTTP_ALLOWED.String(), "true")
		if result := env.IsHTTPAllowed(); !result {
			t.Fatalf("Set debug mode on, but result is %v", result)
		}
	})
}
