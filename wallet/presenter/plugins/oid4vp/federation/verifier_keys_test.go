package federation

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// signJWKSet signs a JWK Set JWT (OpenID Federation 1.0 Section 5.2.1) with
// key, typed typ.
func signJWKSet(t *testing.T, key signingKey, typ string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key.private, KeyID: key.kid}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)),
	)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func requireRequestKey(t *testing.T, trust *VerifierTrust, want signingKey) {
	t.Helper()
	if len(trust.RequestObjectJWKS.Keys) != 1 || !reflect.DeepEqual(trust.RequestObjectJWKS.Keys[0].Key, want.jwks.Keys[0].Key) {
		t.Fatalf("RequestObjectJWKS = %+v, want the metadata key %s", trust.RequestObjectJWKS, want.kid)
	}
}

// TestVerifierRequestObjectKeysComeFromEntityTypeMetadata covers OpenID
// Federation 1.0 Section 12.1.1.1.2: the Request Object is verified "using the
// key material the client published in its metadata" for its Entity Type, and
// Section 5.2.1: those keys "are distinct from the Federation Entity Keys".
func TestVerifierRequestObjectKeysComeFromEntityTypeMetadata(t *testing.T) {
	t.Run("jwks is used and the Federation Entity Keys are not", func(t *testing.T) {
		f := newDirectFederation(t, directOptions{verifierMetadata: verifierFederationMetadata(nil)})
		trust, err := offlineResolver(t, f.anchors()).ResolveVerifierTrust(context.Background(), f.verifier, f.chain, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireRequestKey(t, trust, f.requestKey)
		for _, key := range trust.RequestObjectJWKS.Keys {
			if reflect.DeepEqual(key.Key, f.verifierKey.jwks.Keys[0].Key) {
				t.Fatal("a Federation Entity Key must not verify a Request Object")
			}
		}
	})

	t.Run("no published key is refused", func(t *testing.T) {
		f := newDirectFederation(t, directOptions{verifierMetadata: verifierFederationMetadata(nil), keepVerifierKeys: true})
		_, err := offlineResolver(t, f.anchors()).ResolveVerifierTrust(context.Background(), f.verifier, f.chain, nil)
		requireCode(t, err, ErrVerifierKeysUnavailable, "publishes no jwks, signed_jwks_uri or jwks_uri")
	})

	t.Run("encryption keys are left out", func(t *testing.T) {
		encryption := newSigningKey(t, "encryption-key")
		encryption.jwks.Keys[0].Use = "enc"
		metadata := verifierFederationMetadata(nil)
		metadata[VerifierEntityType].(map[string]any)["jwks"] = encryption.jwks
		f := newDirectFederation(t, directOptions{verifierMetadata: metadata, keepVerifierKeys: true})
		_, err := offlineResolver(t, f.anchors()).ResolveVerifierTrust(context.Background(), f.verifier, f.chain, nil)
		requireCode(t, err, ErrVerifierKeysUnavailable, "no signing key")
	})
}

// TestVerifierRequestObjectKeysFromURIs covers the two JWK Set references of
// OpenID Federation 1.0 Section 5.2.1.
func TestVerifierRequestObjectKeysFromURIs(t *testing.T) {
	setup := func(t *testing.T, member, path string) *directFederation {
		return newDirectFederation(t, directOptions{
			verifierMetadata: verifierFederationMetadata(nil),
			keepVerifierKeys: true,
			verifierPaths:    map[string]string{member: path},
		})
	}
	resolve := func(f *directFederation) (*VerifierTrust, error) {
		return f.resolver().ResolveVerifierTrust(context.Background(), f.verifier, f.chain, nil)
	}
	publicKeys := func(key signingKey) any {
		encoded, _ := json.Marshal(key.jwks)
		var decoded map[string]any
		_ = json.Unmarshal(encoded, &decoded)
		return decoded["keys"]
	}

	signedCases := []struct {
		name   string
		signer func(f *directFederation) signingKey
		typ    string
		claims func(f *directFederation) map[string]any
		want   string
	}{
		{
			name:   "signed with a Federation Entity Key",
			signer: func(f *directFederation) signingKey { return f.verifierKey },
			typ:    signedJWKSTyp,
		},
		{
			name:   "signed by a key that is not a Federation Entity Key",
			signer: func(f *directFederation) signingKey { return f.requestKey },
			typ:    signedJWKSTyp,
			want:   "not signed with a Federation Entity Key",
		},
		{
			name:   "wrong typ",
			signer: func(f *directFederation) signingKey { return f.verifierKey },
			typ:    "JWT",
			want:   "typ must be jwk-set+jwt",
		},
		{
			name:   "another subject",
			signer: func(f *directFederation) signingKey { return f.verifierKey },
			typ:    signedJWKSTyp,
			claims: func(f *directFederation) map[string]any {
				return map[string]any{"keys": publicKeys(f.requestKey), "iss": f.anchor, "sub": f.anchor}
			},
			want: "sub must be the verifier's Entity Identifier",
		},
		{
			name:   "expired",
			signer: func(f *directFederation) signingKey { return f.verifierKey },
			typ:    signedJWKSTyp,
			claims: func(f *directFederation) map[string]any {
				return map[string]any{"keys": publicKeys(f.requestKey), "iss": f.verifier, "sub": f.verifier, "exp": testNow.Unix() - 1}
			},
			want: "expired",
		},
	}
	for _, tc := range signedCases {
		t.Run("signed_jwks_uri "+tc.name, func(t *testing.T) {
			f := setup(t, "signed_jwks_uri", "/verifier/signed-jwks")
			claims := map[string]any{"keys": publicKeys(f.requestKey), "iss": f.verifier, "sub": f.verifier}
			if tc.claims != nil {
				claims = tc.claims(f)
			}
			f.server.serve(f.server.URL+"/verifier/signed-jwks", signJWKSet(t, tc.signer(f), tc.typ, claims), signedJWKSMediaType)
			trust, err := resolve(f)
			if tc.want != "" {
				requireCode(t, err, ErrVerifierKeysUnavailable, tc.want)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			requireRequestKey(t, trust, f.requestKey)
		})
	}

	t.Run("jwks_uri", func(t *testing.T) {
		f := setup(t, "jwks_uri", "/verifier/jwks")
		encoded, err := json.Marshal(f.requestKey.jwks)
		if err != nil {
			t.Fatal(err)
		}
		f.server.serve(f.server.URL+"/verifier/jwks", string(encoded), "application/json")
		trust, err := resolve(f)
		if err != nil {
			t.Fatal(err)
		}
		requireRequestKey(t, trust, f.requestKey)
	})

	t.Run("jwks_uri must use https", func(t *testing.T) {
		metadata := verifierFederationMetadata(nil)
		metadata[VerifierEntityType].(map[string]any)["jwks_uri"] = "http://verifier.example.test/jwks"
		f := newDirectFederation(t, directOptions{verifierMetadata: metadata, keepVerifierKeys: true})
		_, err := resolve(f)
		requireCode(t, err, ErrVerifierKeysUnavailable, "jwks_uri must be an https URL")
	})
}
