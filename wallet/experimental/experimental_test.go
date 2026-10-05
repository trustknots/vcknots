package experimental_test

import (
	"testing"

	"github.com/trustknots/vcknots/wallet/experimental"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

func TestHooksSet(t *testing.T) {
	identity := func(proof string) (string, error) { return proof, nil }
	content := func(c experimental.ProofJWTContent) (experimental.ProofJWTContent, error) { return c, nil }
	response := func(vp []byte, s presenterTypes.PresentationSubmission) ([]byte, presenterTypes.PresentationSubmission, error) {
		return vp, s, nil
	}
	for name, test := range map[string]struct {
		hooks experimental.Hooks
		want  bool
	}{
		"zero":                  {experimental.Hooks{}, false},
		"empty key proof":       {experimental.Hooks{KeyProof: experimental.ProofTransform{}}, false},
		"key proof content":     {experimental.Hooks{KeyProof: experimental.ProofTransform{Content: content}}, true},
		"key proof serialized":  {experimental.Hooks{KeyProof: experimental.ProofTransform{Serialized: identity}}, true},
		"presentation exchange": {experimental.Hooks{PresentationExchangeResponse: response}, true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := test.hooks.Set(); got != test.want {
				t.Fatalf("Set() = %v, want %v", got, test.want)
			}
		})
	}
}

// The zero value of every type is the specification-conforming behavior.
func TestZeroValuesConform(t *testing.T) {
	if (experimental.Transport{}).AllowHTTP {
		t.Fatal("the zero Transport allows http")
	}
	if (experimental.Options{}).Hooks.Set() {
		t.Fatal("the zero Options set a hook")
	}
	if zero := (experimental.Presenter{}); zero.Transport.AllowHTTP || zero.InsecureSkipX509Verify || zero.AcceptClientMetadataJWKsWithoutKeyID {
		t.Fatal("the zero Presenter relaxes something")
	}
}
