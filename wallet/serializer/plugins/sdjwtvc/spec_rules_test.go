package sdjwtvc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/serializer/types"
)

// unsignedSDJWT builds an SD-JWT VC whose payload is claims plus an _sd array
// committing to one Disclosure per entry of disclosed. The signature is not
// meaningful: deserialization does not verify it.
func unsignedSDJWT(t *testing.T, claims map[string]any, disclosed map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"dc+sd-jwt"}`))
	payload := map[string]any{"vct": "urn:test", "iss": "https://issuer.example.test"}
	for name, value := range claims {
		payload[name] = value
	}
	var disclosures, digests []string
	for name, value := range disclosed {
		raw, err := json.Marshal([]any{"salt-" + name, name, value})
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		disclosures = append(disclosures, encoded)
		digest := sha256.Sum256([]byte(encoded))
		digests = append(digests, base64.RawURLEncoding.EncodeToString(digest[:]))
	}
	if len(digests) > 0 {
		payload["_sd"] = digests
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	jwt := header + "." + base64.RawURLEncoding.EncodeToString(body) + "." + signature
	return strings.Join(append([]string{jwt}, disclosures...), "~") + "~"
}

// RFC 9901 §4.1.1 and §7.1: an _sd_alg the recipient does not understand is
// refused, never read as the sha-256 default.
func TestDeserializeCredentialRefusesUnknownSDAlg(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	require.NoError(t, err)

	for name, value := range map[string]any{"unknown hash": "sha-1", "not a string": 256, "empty": ""} {
		t.Run(name, func(t *testing.T) {
			raw := unsignedSDJWT(t, map[string]any{"_sd_alg": value}, map[string]any{"given_name": "Alice"})
			_, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte(raw))
			require.ErrorIs(t, err, types.ErrInvalidCredential)

			_, err = ReconstructClaimsObject(raw)
			require.ErrorIs(t, err, types.ErrInvalidCredential)
		})
	}

	t.Run("an absent _sd_alg is sha-256", func(t *testing.T) {
		raw := unsignedSDJWT(t, nil, map[string]any{"given_name": "Alice"})
		parsed, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte(raw))
		require.NoError(t, err)
		require.Equal(t, "sha-256", parsed.SDJwt.SDAlg)
		require.Equal(t, "Alice", (*parsed.Claims)["given_name"])
	})
}

// SD-JWT VC §2.2.2.3: iss, nbf, exp, cnf, vct, vct#integrity, aka_vcts and
// status, "including any of their sub-claims", MUST NOT be included in
// Disclosures.
func TestDeserializeCredentialRefusesDisclosedRegisteredClaims(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	require.NoError(t, err)

	disclosed := map[string]any{
		"iss":           "https://victim.example",
		"nbf":           1,
		"exp":           1,
		"cnf":           map[string]any{"jwk": map[string]any{"kty": "EC"}},
		"vct":           "urn:other",
		"vct#integrity": "sha256-abc",
		"aka_vcts":      []any{"urn:other"},
		"status":        map[string]any{"status_list": map[string]any{"idx": 0, "uri": "https://status.example"}},
	}
	for name, value := range disclosed {
		t.Run(name+" disclosed", func(t *testing.T) {
			// The plaintext default is dropped so the refusal is the
			// disclosure, not an overwrite of a plaintext claim.
			raw := unsignedSDJWTWithout(t, name, map[string]any{name: value})
			_, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte(raw))
			require.ErrorIs(t, err, types.ErrInvalidCredential)
			require.ErrorIs(t, err, types.ErrInvalidCredential)
		})
	}

	for _, name := range []string{"cnf", "status"} {
		t.Run("a sub-claim of "+name+" disclosed", func(t *testing.T) {
			raw := unsignedSDJWT(t, map[string]any{name: map[string]any{"_sd": []any{"digest"}}}, nil)
			_, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte(raw))
			require.ErrorIs(t, err, types.ErrInvalidCredential)
		})
	}
	t.Run("an aka_vcts element disclosed", func(t *testing.T) {
		raw := unsignedSDJWT(t, map[string]any{"aka_vcts": []any{map[string]any{"...": "digest"}}}, nil)
		_, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte(raw))
		require.ErrorIs(t, err, types.ErrInvalidCredential)
	})

	t.Run("sub and iat may be disclosed", func(t *testing.T) {
		raw := unsignedSDJWT(t, nil, map[string]any{"sub": "user", "iat": 1})
		_, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte(raw))
		require.NoError(t, err)
	})
	t.Run("a nested claim named iss is not the registered claim", func(t *testing.T) {
		raw := unsignedSDJWT(t, nil, map[string]any{"employer": map[string]any{"iss": "anything"}})
		_, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte(raw))
		require.NoError(t, err)
	})
}

// unsignedSDJWTWithout is unsignedSDJWT with the plaintext claim omitted
// removed from the payload.
func unsignedSDJWTWithout(t *testing.T, omitted string, disclosed map[string]any) string {
	t.Helper()
	raw := unsignedSDJWT(t, nil, disclosed)
	jwt, rest, _ := strings.Cut(raw, "~")
	parts := strings.Split(jwt, ".")
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(body, &payload))
	delete(payload, omitted)
	body, err = json.Marshal(payload)
	require.NoError(t, err)
	parts[1] = base64.RawURLEncoding.EncodeToString(body)
	return strings.Join(parts, ".") + "~" + rest
}
