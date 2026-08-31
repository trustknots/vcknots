package clientconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/keystore"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// keyEntryFor builds the out-of-band signing key used by WithKeyEntry tests.
func keyEntryFor(t *testing.T, privateJWK jose.JSONWebKey) (wallet.IKeyEntry, error) {
	t.Helper()
	return keystore.NewKeyEntryFromJWK(privateJWK)
}

// newKeyPair returns a private JWK and its public counterpart, both carrying
// the given kid and alg.
func newKeyPair(t *testing.T, curve elliptic.Curve, keyID, alg string) (jose.JSONWebKey, jose.JSONWebKey) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	private := jose.JSONWebKey{Key: privKey, KeyID: keyID, Algorithm: alg, Use: "sig"}
	return private, private.Public()
}

func writeJSON(t *testing.T, dir, name string, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

// documentWith builds a single-client document registering publicJWK.
func documentWith(publicJWK jose.JSONWebKey, clientID, method, alg, audience string) Document {
	return Document{
		Clients: []Client{{
			ClientID:                    clientID,
			TokenEndpointAuthMethod:     method,
			TokenEndpointAuthSigningAlg: alg,
			ClientAssertionAudience:     audience,
			JWKS:                        &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK}},
		}},
	}
}

func TestLoad_PrivateKeyJWTFromSeparateFiles(t *testing.T) {
	dir := t.TempDir()
	private, public := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")

	configPath := writeJSON(t, dir, "wallet-clients.json",
		documentWith(public, "wallet-id", "private_key_jwt", "ES256", "https://authz.example.com"))
	keyPath := writeJSON(t, dir, "client-private.jwks.json",
		jose.JSONWebKeySet{Keys: []jose.JSONWebKey{private}})

	clientAuth, err := Load(configPath, WithPrivateJWKFile(keyPath))
	require.NoError(t, err)

	assert.Equal(t, receiverTypes.PrivateKeyJwt, clientAuth.Method)
	assert.Equal(t, "wallet-id", clientAuth.ClientID)
	assert.Equal(t, "https://authz.example.com", clientAuth.AssertionAudience)
	assert.Equal(t, jose.ES256, clientAuth.SigningAlg)
	require.NotNil(t, clientAuth.Key)
	assert.Equal(t, "client-key-1", clientAuth.Key.PublicKey().KeyID)
}

func TestParse_DefaultsSigningAlgToES256(t *testing.T) {
	private, public := newKeyPair(t, elliptic.P256(), "client-key-1", "")
	document := documentWith(public, "wallet-id", "private_key_jwt", "", "")

	data, err := json.Marshal(document)
	require.NoError(t, err)

	key, err := keyEntryFor(t, private)
	require.NoError(t, err)

	clientAuth, err := Parse(data, WithKeyEntry(key))
	require.NoError(t, err)

	assert.Equal(t, jose.ES256, clientAuth.SigningAlg)
	// An empty audience keeps the wallet resolving aud from the authorization
	// server metadata issuer.
	assert.Empty(t, clientAuth.AssertionAudience)
}

func TestParse_AcceptsSingularClientKey(t *testing.T) {
	private, public := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")
	document := Document{
		Client: []Client{{
			ClientID:                "wallet-id",
			TokenEndpointAuthMethod: "private_key_jwt",
			JWKS:                    &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}},
		}},
	}
	data, err := json.Marshal(document)
	require.NoError(t, err)

	key, err := keyEntryFor(t, private)
	require.NoError(t, err)

	clientAuth, err := Parse(data, WithKeyEntry(key))
	require.NoError(t, err)
	assert.Equal(t, "wallet-id", clientAuth.ClientID)
}

func TestParse_SelectsClientByID(t *testing.T) {
	privateA, publicA := newKeyPair(t, elliptic.P256(), "key-a", "ES256")
	_, publicB := newKeyPair(t, elliptic.P256(), "key-b", "ES256")

	document := Document{Clients: []Client{
		{
			ClientID:                "wallet-a",
			TokenEndpointAuthMethod: "private_key_jwt",
			JWKS:                    &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicA}},
		},
		{
			ClientID:                "wallet-b",
			TokenEndpointAuthMethod: "private_key_jwt",
			JWKS:                    &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicB}},
		},
	}}
	data, err := json.Marshal(document)
	require.NoError(t, err)

	key, err := keyEntryFor(t, privateA)
	require.NoError(t, err)

	_, err = Parse(data, WithKeyEntry(key))
	require.ErrorIs(t, err, ErrAmbiguousClient)

	clientAuth, err := Parse(data, WithClientID("wallet-a"), WithKeyEntry(key))
	require.NoError(t, err)
	assert.Equal(t, "wallet-a", clientAuth.ClientID)

	_, err = Parse(data, WithClientID("wallet-c"), WithKeyEntry(key))
	require.ErrorIs(t, err, ErrClientNotFound)
}

func TestParse_RejectsDuplicateClientID(t *testing.T) {
	_, public := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")
	document := Document{Clients: []Client{
		{ClientID: "wallet-id", TokenEndpointAuthMethod: "private_key_jwt", JWKS: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}}},
		{ClientID: "wallet-id", TokenEndpointAuthMethod: "private_key_jwt", JWKS: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}}},
	}}
	data, err := json.Marshal(document)
	require.NoError(t, err)

	_, err = Parse(data, WithClientID("wallet-id"))
	require.ErrorIs(t, err, ErrDuplicateClientID)
}

func TestParse_RejectsPrivateKeyInJWKS(t *testing.T) {
	private, _ := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")
	document := documentWith(private, "wallet-id", "private_key_jwt", "ES256", "")

	data, err := json.Marshal(document)
	require.NoError(t, err)

	_, err = Parse(data)
	require.ErrorIs(t, err, ErrPrivateKeyInJWKS)
}

// rawDocument renders a client entry with jwks written verbatim, so that a
// bare JWK can be placed where a JWK Set belongs.
func rawDocument(t *testing.T, method, jwksJSON string) []byte {
	t.Helper()
	return []byte(`{"clients":[{"client_id":"wallet-id",` +
		`"token_endpoint_auth_method":"` + method + `",` +
		`"jwks":` + jwksJSON + `}]}`)
}

func TestParse_RejectsJWKSThatIsNotAKeySet(t *testing.T) {
	private, public := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")

	publicJSON, err := json.Marshal(public)
	require.NoError(t, err)
	privateJSON, err := json.Marshal(private)
	require.NoError(t, err)

	key, err := keyEntryFor(t, private)
	require.NoError(t, err)

	// A bare JWK unmarshals into a JWK Set with no keys, which would leave the
	// private key check and the registration comparison with nothing to look at.
	_, err = Parse(rawDocument(t, "private_key_jwt", string(publicJSON)), WithKeyEntry(key))
	require.ErrorIs(t, err, ErrInvalidDocument)

	_, err = Parse(rawDocument(t, "private_key_jwt", string(privateJSON)), WithKeyEntry(key))
	require.ErrorIs(t, err, ErrInvalidDocument)

	_, err = Parse(rawDocument(t, "private_key_jwt", `{}`), WithKeyEntry(key))
	require.ErrorIs(t, err, ErrInvalidDocument)
}

func TestParse_ChecksJWKSEvenWhenClientSignsNothing(t *testing.T) {
	private, _ := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")
	document := documentWith(private, "wallet-id", "none", "", "")

	data, err := json.Marshal(document)
	require.NoError(t, err)

	_, err = Parse(data)
	require.ErrorIs(t, err, ErrPrivateKeyInJWKS)
}

func TestParse_RejectsSigningKeySuppliedForNone(t *testing.T) {
	private, public := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")
	document := documentWith(public, "wallet-id", "none", "", "")

	data, err := json.Marshal(document)
	require.NoError(t, err)

	key, err := keyEntryFor(t, private)
	require.NoError(t, err)

	// Silently dropping the key would hand back an anonymous configuration
	// while the caller believes client authentication is on.
	_, err = Parse(data, WithKeyEntry(key))
	require.ErrorIs(t, err, ErrUnusedSigningKey)

	_, err = Parse(data, WithPrivateJWKFile("client-private.jwks.json"))
	require.ErrorIs(t, err, ErrUnusedSigningKey)
}

func TestParse_RejectsUnsupportedValues(t *testing.T) {
	_, public := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")

	t.Run("auth method", func(t *testing.T) {
		document := documentWith(public, "wallet-id", "client_secret_basic", "ES256", "")
		data, err := json.Marshal(document)
		require.NoError(t, err)

		_, err = Parse(data)
		require.ErrorIs(t, err, ErrUnsupportedAuthMethod)
	})

	t.Run("signing algorithm", func(t *testing.T) {
		document := documentWith(public, "wallet-id", "private_key_jwt", "RS256", "")
		data, err := json.Marshal(document)
		require.NoError(t, err)

		_, err = Parse(data)
		require.ErrorIs(t, err, ErrUnsupportedSigningAlg)
	})

	t.Run("unknown signing algorithm", func(t *testing.T) {
		document := documentWith(public, "wallet-id", "private_key_jwt", "HS256", "")
		data, err := json.Marshal(document)
		require.NoError(t, err)

		_, err = Parse(data)
		require.ErrorIs(t, err, ErrUnsupportedSigningAlg)
	})
}

func TestParse_RejectsAlgMismatchBetweenJWKAndMetadata(t *testing.T) {
	_, public := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")
	document := documentWith(public, "wallet-id", "private_key_jwt", "ES384", "")

	data, err := json.Marshal(document)
	require.NoError(t, err)

	_, err = Parse(data)
	require.ErrorIs(t, err, ErrSigningAlgMismatch)
}

func TestParse_RejectsJWKSAndJWKSURITogether(t *testing.T) {
	_, public := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")
	document := Document{Clients: []Client{{
		ClientID:                "wallet-id",
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKS:                    &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}},
		JWKSURI:                 "https://wallet.example.com/jwks.json",
	}}}
	data, err := json.Marshal(document)
	require.NoError(t, err)

	_, err = Parse(data)
	require.ErrorIs(t, err, ErrJWKSConflict)
}

func TestParse_RejectsJWKSURIWithoutLocalKey(t *testing.T) {
	document := Document{Clients: []Client{{
		ClientID:                "wallet-id",
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKSURI:                 "https://wallet.example.com/jwks.json",
	}}}
	data, err := json.Marshal(document)
	require.NoError(t, err)

	_, err = Parse(data)
	require.ErrorIs(t, err, ErrJWKSURIUnsupported)
}

func TestParse_RequiresPrivateKeyWhenOnlyPublicIsRegistered(t *testing.T) {
	_, public := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")
	document := documentWith(public, "wallet-id", "private_key_jwt", "ES256", "")

	data, err := json.Marshal(document)
	require.NoError(t, err)

	_, err = Parse(data)
	require.ErrorIs(t, err, ErrSigningKeyNotFound)
}

func TestParse_RejectsKeyThatDoesNotMatchRegistration(t *testing.T) {
	_, registeredPublic := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")
	otherPrivate, _ := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")

	document := documentWith(registeredPublic, "wallet-id", "private_key_jwt", "ES256", "")
	data, err := json.Marshal(document)
	require.NoError(t, err)

	key, err := keyEntryFor(t, otherPrivate)
	require.NoError(t, err)

	_, err = Parse(data, WithKeyEntry(key))
	require.ErrorIs(t, err, ErrKeyMismatch)
}

func TestParse_SelectsSigningKeyByKeyID(t *testing.T) {
	privateA, publicA := newKeyPair(t, elliptic.P256(), "key-a", "ES256")
	_, publicB := newKeyPair(t, elliptic.P256(), "key-b", "ES256")

	document := Document{Clients: []Client{{
		ClientID:                "wallet-id",
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKS:                    &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicA, publicB}},
	}}}
	data, err := json.Marshal(document)
	require.NoError(t, err)

	key, err := keyEntryFor(t, privateA)
	require.NoError(t, err)

	_, err = Parse(data, WithKeyEntry(key))
	require.ErrorIs(t, err, ErrAmbiguousSigningKey)

	clientAuth, err := Parse(data, WithKeyID("key-a"), WithKeyEntry(key))
	require.NoError(t, err)
	assert.Equal(t, "key-a", clientAuth.Key.PublicKey().KeyID)
}

func TestParse_SkipsEncryptionOnlyKeys(t *testing.T) {
	privateSig, publicSig := newKeyPair(t, elliptic.P256(), "key-sig", "ES256")
	_, publicEnc := newKeyPair(t, elliptic.P256(), "key-enc", "ES256")
	publicEnc.Use = "enc"

	document := Document{Clients: []Client{{
		ClientID:                "wallet-id",
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKS:                    &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicEnc, publicSig}},
	}}}
	data, err := json.Marshal(document)
	require.NoError(t, err)

	key, err := keyEntryFor(t, privateSig)
	require.NoError(t, err)

	clientAuth, err := Parse(data, WithKeyEntry(key))
	require.NoError(t, err)
	assert.Equal(t, "key-sig", clientAuth.Key.PublicKey().KeyID)
}

func TestParse_NoneNeedsNoKey(t *testing.T) {
	document := Document{Clients: []Client{{
		ClientID:                "wallet-id",
		TokenEndpointAuthMethod: "none",
	}}}
	data, err := json.Marshal(document)
	require.NoError(t, err)

	clientAuth, err := Parse(data)
	require.NoError(t, err)
	assert.Equal(t, receiverTypes.None, clientAuth.Method)
	assert.Nil(t, clientAuth.Key)
}

func TestWithAssertionAudience_Overrides(t *testing.T) {
	private, public := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")
	document := documentWith(public, "wallet-id", "private_key_jwt", "ES256", "https://configured.example.com")

	data, err := json.Marshal(document)
	require.NoError(t, err)

	key, err := keyEntryFor(t, private)
	require.NoError(t, err)

	clientAuth, err := Parse(data, WithKeyEntry(key), WithAssertionAudience("https://override.example.com"))
	require.NoError(t, err)
	assert.Equal(t, "https://override.example.com", clientAuth.AssertionAudience)

	cleared, err := Parse(data, WithKeyEntry(key), WithAssertionAudience(""))
	require.NoError(t, err)
	assert.Empty(t, cleared.AssertionAudience)
}

func TestLoad_RejectsWorldReadablePrivateKeyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not enforced on Windows")
	}

	dir := t.TempDir()
	private, public := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")

	configPath := writeJSON(t, dir, "wallet-clients.json",
		documentWith(public, "wallet-id", "private_key_jwt", "ES256", ""))
	keyPath := writeJSON(t, dir, "client-private.jwks.json",
		jose.JSONWebKeySet{Keys: []jose.JSONWebKey{private}})
	require.NoError(t, os.Chmod(keyPath, 0o644))

	_, err := Load(configPath, WithPrivateJWKFile(keyPath))
	require.ErrorIs(t, err, ErrInsecureFilePermissions)

	_, err = Load(configPath, WithPrivateJWKFile(keyPath), AllowInsecureFilePermissions())
	require.NoError(t, err)
}

func TestLoad_AcceptsBareJWKPrivateKeyFile(t *testing.T) {
	dir := t.TempDir()
	private, public := newKeyPair(t, elliptic.P256(), "client-key-1", "ES256")

	configPath := writeJSON(t, dir, "wallet-clients.json",
		documentWith(public, "wallet-id", "private_key_jwt", "ES256", ""))
	keyPath := writeJSON(t, dir, "client-private.jwk", private)

	clientAuth, err := Load(configPath, WithPrivateJWKFile(keyPath))
	require.NoError(t, err)
	assert.Equal(t, "client-key-1", clientAuth.Key.PublicKey().KeyID)
}

func TestLoadDocument_ReturnsEntriesInFileOrder(t *testing.T) {
	dir := t.TempDir()
	_, publicA := newKeyPair(t, elliptic.P256(), "key-a", "ES256")
	_, publicB := newKeyPair(t, elliptic.P256(), "key-b", "ES256")

	path := writeJSON(t, dir, "wallet-clients.json", Document{
		Clients: []Client{{ClientID: "wallet-a", JWKS: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicA}}}},
		Client:  []Client{{ClientID: "wallet-b", JWKS: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicB}}}},
	})

	document, err := LoadDocument(path)
	require.NoError(t, err)

	entries := document.Entries()
	require.Len(t, entries, 2)
	assert.Equal(t, "wallet-a", entries[0].ClientID)
	assert.Equal(t, "wallet-b", entries[1].ClientID)
}

func TestLoad_ReportsMissingAndMalformedFiles(t *testing.T) {
	dir := t.TempDir()

	_, err := Load(filepath.Join(dir, "absent.json"))
	require.ErrorIs(t, err, fs.ErrNotExist)

	brokenPath := filepath.Join(dir, "broken.json")
	require.NoError(t, os.WriteFile(brokenPath, []byte("{"), 0o600))

	_, err = Load(brokenPath)
	require.ErrorIs(t, err, ErrInvalidDocument)

	emptyPath := filepath.Join(dir, "empty.json")
	require.NoError(t, os.WriteFile(emptyPath, []byte("{}"), 0o600))

	_, err = Load(emptyPath)
	require.ErrorIs(t, err, ErrNoClientEntries)
}
