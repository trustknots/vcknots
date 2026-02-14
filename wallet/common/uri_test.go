package common

import (
	"encoding/json"
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