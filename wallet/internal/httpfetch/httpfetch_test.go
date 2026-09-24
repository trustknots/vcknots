package httpfetch

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func response(body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{Header: header, Body: io.NopCloser(strings.NewReader(body))}
}

func TestReadLimited(t *testing.T) {
	t.Run("within the limit", func(t *testing.T) {
		body, err := ReadLimited(response("abc", nil), 3)
		if err != nil || string(body) != "abc" {
			t.Fatalf("got %q, %v", body, err)
		}
	})
	t.Run("delivered beyond the limit", func(t *testing.T) {
		_, err := ReadLimited(response("abcd", nil), 3)
		if !errors.Is(err, ErrBodyTooLarge) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("declared beyond the limit", func(t *testing.T) {
		_, err := ReadLimited(response("a", http.Header{"Content-Length": {"10"}}), 3)
		if !errors.Is(err, ErrBodyTooLarge) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("invalid Content-Length", func(t *testing.T) {
		_, err := ReadLimited(response("a", http.Header{"Content-Length": {"-1"}}), 3)
		if err == nil || errors.Is(err, ErrBodyTooLarge) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestMediaTypeIs(t *testing.T) {
	header := http.Header{"Content-Type": {"Application/JSON; charset=utf-8"}}
	if !MediaTypeIs(header, "application/json") {
		t.Fatal("expected a match with parameters and case ignored")
	}
	if MediaTypeIs(http.Header{"Content-Type": {"application/jsonx"}}, "application/json") {
		t.Fatal("a different media type must not match")
	}
	if MediaTypeIs(http.Header{}, "application/json") {
		t.Fatal("an absent header must not match")
	}
}

func TestNoRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the redirect target must not be requested")
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	base := &http.Client{}
	resp, err := NoRedirect(base).Post(origin.URL, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if base.CheckRedirect != nil {
		t.Fatal("the caller's client must not be modified")
	}
	if NoRedirect(nil).Timeout != DefaultTimeout {
		t.Fatal("a nil client yields the default client")
	}
}
