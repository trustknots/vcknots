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

func TestIsDebugMode(t *testing.T) {
	t.Run("check", func(t *testing.T) {
		dbg_mode := env.IsDebugMode()
		defer env.SetDebugMode(dbg_mode)

		os.Setenv(env.DEBUG.String(), "true")
		if result := env.IsDebugMode(); !result {
			t.Fatalf("Set debug mode on, but result is %v", result)
		}

		os.Setenv(env.DEBUG.String(), "false")
		if result := env.IsDebugMode(); result {
			t.Fatalf("Set debug mode on, but result is %v", result)
		}
	})
}
