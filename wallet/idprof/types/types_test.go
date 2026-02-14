package types

import (
	"fmt"
	"testing"
)

func TestIdentityProfileErrorError(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		e := IdentityProfileError{
			TypeID: "hoge",
			ID:     "fuga",
			Op:     "piyo",
			Err:    fmt.Errorf("error"),
		}
		errStr := e.Error()
		expected := fmt.Sprintf("identity profile %s (type: %s) operation %s: %v", e.ID, e.TypeID, e.Op, e.Err)
		if errStr != expected {
			t.Errorf("Invalid error: %v, expected = %v", errStr, expected)
		}
	})

	t.Run("Empty ID", func(t *testing.T) {
		e := IdentityProfileError{
			TypeID: "hoge",
			ID:     "",
			Op:     "piyo",
			Err:    fmt.Errorf("error"),
		}
		errStr := e.Error()
		expected := fmt.Sprintf("identity profile type %s operation %s: %v", e.TypeID, e.Op, e.Err)
		if errStr != expected {
			t.Errorf("Invalid error: %v, expected = %v", errStr, expected)
		}
	})
}

func TestNewCreateConfig(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		config := NewCreateConfig()
		if len(config.params) != 0 {
			t.Errorf("Params should be empty")
		}
	})
}

func TestNewUpdateConfig(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		config := NewUpdateConfig()
		if len(config.params) != 0 {
			t.Errorf("Params should be empty")
		}
	})
}

func TestCreateConfigSet(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		config := NewCreateConfig()
		config.Set("hoge", "piyo")
		if config.params["hoge"] != "piyo" {
			t.Errorf("Failed to set param")
		}
	})
}

func TestCreateConfigGet(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		config := NewCreateConfig()
		config.Set("hoge", "piyo")
		result, has := config.Get("hoge")
		if !has || result != "piyo" {
			t.Fatalf("Failed to get param")
		}

		_, has = config.Get("NotExist")
		if has {
			t.Fatalf("Get() should return false when key doesn't exist")
		}
	})
}

func TestCreateConfigHas(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		config := NewCreateConfig()
		config.Set("hoge", "piyo")
		has := config.Has("hoge")
		if !has {
			t.Errorf("Failed to check param")
		}

		has = config.Has("NotExist")
		if has {
			t.Errorf("Has() should return false when key doesn't exist")
		}
	})
}

func TestUpdateConfigSet(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		config := NewUpdateConfig()
		config.Set("hoge", "piyo")
		if config.params["hoge"] != "piyo" {
			t.Errorf("Failed to set param")
		}
	})
}

func TestUpdateConfigGet(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		config := NewUpdateConfig()
		config.Set("hoge", "piyo")
		result, has := config.Get("hoge")
		if !has || result != "piyo" {
			t.Errorf("Failed to get param")
		}

		_, has = config.Get("NotExist")
		if has {
			t.Errorf("Get() should return false when key doesn't exist")
		}
	})
}

func TestUpdateConfigHas(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		config := NewUpdateConfig()
		config.Set("hoge", "piyo")
		has := config.Has("hoge")
		if !has {
			t.Errorf("Failed to check param")
		}

		has = config.Has("NotExist")
		if has {
			t.Errorf("Has() should return false when key doesn't exist")
		}
	})
}
