package types

import (
	"encoding/json"
	"testing"
)

// RFC 8414 publishes response_modes_supported as strings; metadata listing
// modes this package does not name must still decode.
func TestAuthorizationServerMetadataDecodesResponseModes(t *testing.T) {
	var metadata AuthorizationServerMetadata
	body := `{"issuer":"https://as.example","response_modes_supported":["query","fragment","form_post"]}`
	if err := json.Unmarshal([]byte(body), &metadata); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := *metadata.ResponseModesSupported
	want := []OAuthResponseMode{Query, Fragment, OtherResponseMode}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if _, err := json.Marshal([]OAuthResponseMode{Query, Fragment}); err != nil {
		t.Fatalf("encode: %v", err)
	}
}
