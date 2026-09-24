package ldpvc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credential/dataintegrity"
	"github.com/trustknots/vcknots/wallet/serializer/types"
)

const testContextURL = "https://example.test/contexts/presentation.jsonld"

var testContexts = dataintegrity.PinnedContexts{
	testContextURL: map[string]any{"@context": map[string]any{
		"id":                     "@id",
		"type":                   "@type",
		"VerifiablePresentation": "https://www.w3.org/2018/credentials#VerifiablePresentation",
		"VerifiableCredential":   "https://www.w3.org/2018/credentials#VerifiableCredential",
		"DataIntegrityProof":     "https://w3id.org/security#DataIntegrityProof",
		"holder":                 map[string]any{"@id": "https://www.w3.org/2018/credentials#holder", "@type": "@id"},
		"verifiableCredential":   map[string]any{"@id": "https://www.w3.org/2018/credentials#verifiableCredential", "@type": "@id"},
		"issuer":                 map[string]any{"@id": "https://www.w3.org/2018/credentials#issuer", "@type": "@id"},
		"name":                   "https://schema.org/name",
		"proof":                  "https://w3id.org/security#proof",
		"cryptosuite":            "https://w3id.org/security#cryptosuite",
		"challenge":              "https://w3id.org/security#challenge",
		"domain":                 "https://w3id.org/security#domain",
		"proofValue":             "https://w3id.org/security#proofValue",
		"authentication":         "https://w3id.org/security#authentication",
		"proofPurpose":           map[string]any{"@id": "https://w3id.org/security#proofPurpose", "@type": "@vocab"},
		"verificationMethod":     map[string]any{"@id": "https://w3id.org/security#verificationMethod", "@type": "@id"},
		"created":                map[string]any{"@id": "http://purl.org/dc/terms/created", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
	}},
}

type edKey struct{ private ed25519.PrivateKey }

func (k edKey) ID() string { return "ed" }
func (k edKey) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{Key: k.private.Public().(ed25519.PublicKey)}
}
func (k edKey) Sign(data []byte) ([]byte, error) { return ed25519.Sign(k.private, data), nil }

type ecKey struct{ private *ecdsa.PrivateKey }

func (k ecKey) ID() string                       { return "ec" }
func (k ecKey) PublicKey() jose.JSONWebKey       { return jose.JSONWebKey{Key: &k.private.PublicKey} }
func (k ecKey) Sign(data []byte) ([]byte, error) { return nil, errors.New("unused") }

func newEdKey() edKey {
	return edKey{private: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))}
}

func TestSerializePresentationBindsTheRequest(t *testing.T) {
	serializer, _ := NewLdpVcSerializer()
	nonce := "fallback-nonce"
	key := newEdKey()
	options := &LdpVcPresentationOptions{Context: testContextURL, Contexts: testContexts, Created: time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)}
	options.SetAudience("x509_san_dns:verifier.example")
	raw, signed, err := serializer.SerializePresentation(credential.LdpVc, &credential.CredentialPresentation{
		ID:          "urn:uuid:presentation",
		Credentials: [][]byte{[]byte(`{"@context":"` + testContextURL + `","type":["VerifiableCredential"],"issuer":"did:example:issuer","name":"Degree"}`)},
		Nonce:       &nonce,
	}, key, options)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	proof := document["proof"].(map[string]any)
	if proof["challenge"] != nonce || proof["domain"] != "x509_san_dns:verifier.example" {
		t.Fatalf("proof binding = %v / %v", proof["challenge"], proof["domain"])
	}
	if proof["created"] != "2026-09-23T00:00:00.000Z" {
		t.Fatalf("created = %v", proof["created"])
	}
	if document["holder"] != signed.Holder || proof["verificationMethod"] != signed.Holder+"#"+signed.Holder[len("did:key:"):] {
		t.Fatalf("holder %v, verificationMethod %v", document["holder"], proof["verificationMethod"])
	}
	if err := dataintegrity.VerifyEddsaRdfc2022(document, testContexts, key.private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if signed.Proof == nil || signed.Proof.Algorithm != jose.EdDSA || len(signed.Proof.Signature) != ed25519.SignatureSize {
		t.Fatalf("returned proof = %#v", signed.Proof)
	}

	parsed, err := serializer.DeserializePresentation(credential.LdpVc, raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != "urn:uuid:presentation" || parsed.Holder != signed.Holder || len(parsed.Credentials) != 1 || parsed.Types[0] != "VerifiablePresentation" {
		t.Fatalf("DeserializePresentation = %#v", parsed)
	}
}

func TestSerializePresentationRefusals(t *testing.T) {
	serializer, _ := NewLdpVcSerializer()
	good := &credential.CredentialPresentation{Credentials: [][]byte{[]byte(`{"@context":"` + testContextURL + `"}`)}}
	options := &LdpVcPresentationOptions{Context: testContextURL, Contexts: testContexts}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	cases := map[string]struct {
		presentation *credential.CredentialPresentation
		key          interface {
			ID() string
			PublicKey() jose.JSONWebKey
			Sign([]byte) ([]byte, error)
		}
		options types.SerializePresentationOptions
		want    error
	}{
		"missing options":       {good, newEdKey(), nil, types.ErrInvalidPresentation},
		"default options":       {good, newEdKey(), &LdpVcPresentationOptions{}, types.ErrInvalidPresentation},
		"no credential":         {&credential.CredentialPresentation{}, newEdKey(), options, types.ErrInvalidPresentation},
		"credential not object": {&credential.CredentialPresentation{Credentials: [][]byte{[]byte(`"jwt"`)}}, newEdKey(), options, types.ErrInvalidCredential},
		"P-256 key":             {good, ecKey{private: ec}, options, types.ErrUnsupportedAlgorithm},
		"foreign holder":        {&credential.CredentialPresentation{Credentials: good.Credentials, Holder: "did:example:other"}, newEdKey(), options, types.ErrInvalidPresentation},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := serializer.SerializePresentation(credential.LdpVc, tc.presentation, tc.key, tc.options)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	if _, _, err := serializer.SerializePresentation(credential.JwtVc, good, newEdKey(), options); !errors.Is(err, types.ErrUnsupportedFormat) {
		t.Fatalf("wrong flavor: %v", err)
	}
}

func TestDeserializeCredential(t *testing.T) {
	serializer, _ := NewLdpVcSerializer()
	parsed, err := serializer.DeserializeCredential(credential.LdpVc, []byte(`{
		"@context": "`+testContextURL+`",
		"id": "urn:uuid:credential",
		"type": ["VerifiableCredential", "UniversityDegreeCredential"],
		"issuer": {"id": "did:example:issuer", "name": "University"},
		"issuanceDate": "2026-01-01T00:00:00Z",
		"validUntil": "2027-01-01T00:00:00Z",
		"credentialSubject": {"id": "did:example:holder", "degreeName": "CS"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != "urn:uuid:credential" || parsed.Issuer != "did:example:issuer" || parsed.Subject != "did:example:holder" {
		t.Fatalf("parsed = %#v", parsed)
	}
	if len(parsed.Types) != 2 || (*parsed.Claims)["degreeName"] != "CS" {
		t.Fatalf("types/claims = %v / %v", parsed.Types, parsed.Claims)
	}
	if parsed.ValidPeriod == nil || parsed.ValidPeriod.From == nil || parsed.ValidPeriod.To == nil {
		t.Fatalf("valid period = %#v", parsed.ValidPeriod)
	}

	for name, raw := range map[string]string{
		"not an object": `"jwt"`,
		"type missing":  `{"issuer":"did:example:issuer"}`,
		"issuer number": `{"type":"VerifiableCredential","issuer":1}`,
		"bad date":      `{"type":"VerifiableCredential","issuer":"did:example:i","validFrom":"yesterday"}`,
	} {
		if _, err := serializer.DeserializeCredential(credential.LdpVc, []byte(raw)); !errors.Is(err, types.ErrInvalidCredential) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}
