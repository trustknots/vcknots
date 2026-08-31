package common

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestParseURIField(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid HTTP URL",
			input:   "https://example.com/path",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL with query",
			input:   "https://example.com/path?query=value",
			wantErr: false,
		},
		{
			name:    "valid relative URL",
			input:   "/path/to/resource",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: false, // url.Parse accepts empty strings
		},
		{
			name:    "invalid URL with control characters",
			input:   "http://example.com\x00",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseURIField(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseURIField() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("ParseURIField() returned nil result without error")
			}
		})
	}
}

func TestURIField_String(t *testing.T) {
	testURL := "https://example.com/path"
	uri, err := ParseURIField(testURL)
	if err != nil {
		t.Fatalf("ParseURIField() failed: %v", err)
	}

	result := uri.String()
	if result != testURL {
		t.Errorf("URIField.String() = %v, want %v", result, testURL)
	}
}

func TestURIField_MarshalJSON(t *testing.T) {
	testURL := "https://example.com/path"
	uri, err := ParseURIField(testURL)
	if err != nil {
		t.Fatalf("ParseURIField() failed: %v", err)
	}

	data, err := json.Marshal(uri)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}

	expected := `"` + testURL + `"`
	if string(data) != expected {
		t.Errorf("URIField.MarshalJSON() = %v, want %v", string(data), expected)
	}
}

func TestURIField_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantURL string
	}{
		{
			name:    "valid JSON URL",
			input:   `"https://example.com/path"`,
			wantErr: false,
			wantURL: "https://example.com/path",
		},
		{
			name:    "invalid JSON",
			input:   `"https://example.com/path`,
			wantErr: true,
		},
		{
			name:    "invalid URL in JSON",
			input:   `"http://example.com\u0000"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var uri URIField
			err := json.Unmarshal([]byte(tt.input), &uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("URIField.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && uri.String() != tt.wantURL {
				t.Errorf("URIField.UnmarshalJSON() result = %v, want %v", uri.String(), tt.wantURL)
			}
		})
	}
}
func TestIsLoopbackHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "literal localhost", host: "localhost", want: true},
		{name: "localhost is case insensitive", host: "LocalHost", want: true},
		{name: "IPv4 loopback", host: "127.0.0.1", want: true},
		{name: "anywhere in 127.0.0.0/8", host: "127.0.0.2", want: true},
		{name: "IPv6 loopback", host: "::1", want: true},
		{name: "IPv4-mapped IPv6 loopback", host: "::ffff:127.0.0.1", want: true},
		{name: "IPv6 loopback with a zone", host: "::1%lo0", want: true},

		// A name that merely contains "localhost" resolves wherever its owner
		// points it, so accepting it would hand the check to DNS.
		{name: "subdomain of an attacker domain", host: "localhost.evil.com", want: false},
		{name: "name ending in localhost", host: "evil-localhost.com", want: false},
		{name: "name starting with localhost", host: "localhostile.example", want: false},
		{name: "fully qualified localhost", host: "localhost.", want: false},

		// Shorthand and integer forms are not valid IP literals in a URL host.
		{name: "dotted shorthand", host: "127.1", want: false},
		{name: "integer form", host: "2130706433", want: false},
		{name: "hexadecimal form", host: "0x7f000001", want: false},

		{name: "unspecified address", host: "0.0.0.0", want: false},
		{name: "private network address", host: "10.0.0.1", want: false},
		{name: "ordinary host name", host: "as.example.com", want: false},
		{name: "empty host", host: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLoopbackHost(tt.host); got != tt.want {
				t.Errorf("IsLoopbackHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestIsLoopbackHost_AcceptsWhatURLHostnameProduces(t *testing.T) {
	// url.Hostname strips the port and the brackets around an IPv6 literal, so
	// the predicate must be fed that form rather than URL.Host.
	tests := []struct {
		rawURL string
		want   bool
	}{
		{rawURL: "http://localhost:8080/token", want: true},
		{rawURL: "http://127.0.0.1:49152/token", want: true},
		{rawURL: "http://[::1]:8080/token", want: true},
		{rawURL: "http://user:pw@localhost:8080/token", want: true},
		{rawURL: "http://as.example.com:8080/token", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.rawURL, func(t *testing.T) {
			parsed, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("failed to parse %q: %v", tt.rawURL, err)
			}
			if got := IsLoopbackHost(parsed.Hostname()); got != tt.want {
				t.Errorf("IsLoopbackHost(%q) = %v, want %v", parsed.Hostname(), got, tt.want)
			}
		})
	}
}
