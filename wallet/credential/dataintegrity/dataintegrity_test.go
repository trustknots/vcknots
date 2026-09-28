package dataintegrity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
)

// referenceVectors are produced by an independent implementation (jsonld.js
// canonize and node:crypto Ed25519) with fixed seeds, so a byte-identical
// proofValue here means both implementations sign the same canonical dataset.
type referenceVectors struct {
	Issuer     vectorKey      `json:"issuer"`
	Holder     vectorKey      `json:"holder"`
	Cases      []vectorCase   `json:"cases"`
	Standard   vectorDocument `json:"standardContextCredential"`
	Contexts   map[string]any `json:"contexts"`
	ContextURL string         `json:"contextUrl"`
}

type vectorKey struct {
	PrivateJWK struct {
		D string `json:"d"`
		X string `json:"x"`
	} `json:"privateJwk"`
	VerificationMethod string `json:"vm"`
}

type vectorCase struct {
	WithStatus         bool           `json:"withStatus"`
	Credential         map[string]any `json:"credential"`
	Presentation       map[string]any `json:"presentation"`
	UnsecuredNQuads    string         `json:"unsecuredNQuads"`
	ProofOptionsNQuads string         `json:"proofOptionsNQuads"`
}

type vectorDocument struct {
	Credential         map[string]any `json:"credential"`
	UnsecuredNQuads    string         `json:"unsecuredNQuads"`
	ProofOptionsNQuads string         `json:"proofOptionsNQuads"`
}

func loadVectors(t *testing.T) referenceVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors referenceVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func (k vectorKey) privateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(k.PrivateJWK.D)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func (k vectorKey) publicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	return k.privateKey(t).Public().(ed25519.PublicKey)
}

func withoutProof(document map[string]any) map[string]any {
	unsecured := map[string]any{}
	for name, value := range document {
		if name != "proof" {
			unsecured[name] = value
		}
	}
	return unsecured
}

func TestCanonicalizeMatchesReferenceVectors(t *testing.T) {
	vectors := loadVectors(t)
	for _, vector := range vectors.Cases {
		got, err := Canonicalize(withoutProof(vector.Presentation), vectors.Contexts)
		if err != nil {
			t.Fatalf("status=%v: %v", vector.WithStatus, err)
		}
		if got != vector.UnsecuredNQuads {
			t.Fatalf("status=%v: canonical N-Quads differ\n got:\n%s\nwant:\n%s", vector.WithStatus, got, vector.UnsecuredNQuads)
		}
	}
	got, err := Canonicalize(withoutProof(vectors.Standard.Credential), vectors.Contexts)
	if err != nil {
		t.Fatal(err)
	}
	if got != vectors.Standard.UnsecuredNQuads {
		t.Fatalf("standard-context credential N-Quads differ\n got:\n%s\nwant:\n%s", got, vectors.Standard.UnsecuredNQuads)
	}
}

func TestVerifyAcceptsReferenceProofs(t *testing.T) {
	vectors := loadVectors(t)
	for _, vector := range vectors.Cases {
		if err := VerifyEddsaRdfc2022(vector.Presentation, vectors.Contexts, vectors.Holder.publicKey(t)); err != nil {
			t.Fatalf("presentation status=%v: %v", vector.WithStatus, err)
		}
		if err := VerifyEddsaRdfc2022(vector.Credential, vectors.Contexts, vectors.Issuer.publicKey(t)); err != nil {
			t.Fatalf("credential status=%v: %v", vector.WithStatus, err)
		}
	}
	// The data-integrity/v2 context is @protected and scopes the proof terms by
	// type; its proof configuration types cryptosuite as cryptosuiteString.
	if err := VerifyEddsaRdfc2022(vectors.Standard.Credential, vectors.Contexts, vectors.Issuer.publicKey(t)); err != nil {
		t.Fatalf("standard-context credential: %v", err)
	}
}

func TestSignReproducesReferenceProofValue(t *testing.T) {
	vectors := loadVectors(t)
	holderKey := vectors.Holder.privateKey(t)
	for _, vector := range vectors.Cases {
		want := vector.Presentation["proof"].(map[string]any)
		created, err := time.Parse(time.RFC3339Nano, want["created"].(string))
		if err != nil {
			t.Fatal(err)
		}
		signed, err := SignEddsaRdfc2022(withoutProof(vector.Presentation), ProofOptions{
			VerificationMethod: vectors.Holder.VerificationMethod,
			ProofPurpose:       ProofPurposeAuthentication,
			Created:            created,
			Challenge:          want["challenge"].(string),
			Domain:             want["domain"].(string),
		}, vectors.Contexts, func(hashData []byte) ([]byte, error) {
			return ed25519.Sign(holderKey, hashData), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		gotProof := signed["proof"].(map[string]any)
		for _, name := range []string{"type", "cryptosuite", "created", "proofPurpose", "verificationMethod", "challenge", "domain", "proofValue"} {
			if gotProof[name] != want[name] {
				t.Fatalf("status=%v: proof %s = %v, reference produced %v", vector.WithStatus, name, gotProof[name], want[name])
			}
		}
	}
}

func TestSignedDocumentVerifiesAndDetectsTampering(t *testing.T) {
	vectors := loadVectors(t)
	holderKey := vectors.Holder.privateKey(t)
	unsecured := withoutProof(vectors.Cases[0].Presentation)
	signed, err := SignEddsaRdfc2022(unsecured, ProofOptions{
		VerificationMethod: vectors.Holder.VerificationMethod,
		ProofPurpose:       ProofPurposeAuthentication,
		Created:            time.Date(2026, 9, 23, 1, 2, 3, 0, time.UTC),
		Challenge:          "nonce",
	}, vectors.Contexts, func(hashData []byte) ([]byte, error) {
		return ed25519.Sign(holderKey, hashData), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := signed["proof"].(map[string]any)["domain"]; present {
		t.Fatal("an empty Domain must not be written into the proof")
	}
	if err := VerifyEddsaRdfc2022(signed, vectors.Contexts, vectors.Holder.publicKey(t)); err != nil {
		t.Fatal(err)
	}

	tampered := map[string]any{}
	for name, value := range signed {
		tampered[name] = value
	}
	tampered["holder"] = "did:example:someone-else"
	if err := VerifyEddsaRdfc2022(tampered, vectors.Contexts, vectors.Holder.publicKey(t)); !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("tampered document: got %v, want ErrProofInvalid", err)
	}

	otherKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if err := VerifyEddsaRdfc2022(signed, vectors.Contexts, otherKey.Public().(ed25519.PublicKey)); !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("wrong key: got %v, want ErrProofInvalid", err)
	}
}

func TestCanonicalizeNeverFetchesAnUnpinnedContext(t *testing.T) {
	vectors := loadVectors(t)
	document := withoutProof(vectors.Cases[0].Credential)
	document["@context"] = []any{vectors.ContextURL, "https://www.w3.org/ns/credentials/v2"}
	_, err := Canonicalize(document, vectors.Contexts)
	if !errors.Is(err, ErrContextNotPinned) {
		t.Fatalf("got %v, want ErrContextNotPinned", err)
	}
	if !strings.Contains(err.Error(), "https://www.w3.org/ns/credentials/v2") {
		t.Fatalf("the refusal should name the unpinned URL: %v", err)
	}
}

func TestCanonicalizeRefusesATermItWouldDrop(t *testing.T) {
	vectors := loadVectors(t)
	document := withoutProof(vectors.Cases[0].Credential)
	document["undefinedClaim"] = "not covered by any context"
	if _, err := Canonicalize(document, vectors.Contexts); !errors.Is(err, ErrCanonicalizationFailed) {
		t.Fatalf("got %v, want ErrCanonicalizationFailed", err)
	}
}

func TestSignRefusesInvalidInput(t *testing.T) {
	vectors := loadVectors(t)
	sign := func([]byte) ([]byte, error) { return make([]byte, ed25519SignatureSize), nil }
	options := ProofOptions{
		VerificationMethod: vectors.Holder.VerificationMethod,
		ProofPurpose:       ProofPurposeAuthentication,
		Created:            time.Now(),
	}
	if _, err := SignEddsaRdfc2022(vectors.Cases[0].Presentation, options, vectors.Contexts, sign); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("secured document: got %v", err)
	}
	unsecured := withoutProof(vectors.Cases[0].Presentation)
	missingMethod := options
	missingMethod.VerificationMethod = " "
	if _, err := SignEddsaRdfc2022(unsecured, missingMethod, vectors.Contexts, sign); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("missing verificationMethod: got %v", err)
	}
	short := func([]byte) ([]byte, error) { return []byte{1, 2, 3}, nil }
	if _, err := SignEddsaRdfc2022(unsecured, options, vectors.Contexts, short); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("short signature: got %v", err)
	}
	failing := func([]byte) ([]byte, error) { return nil, errors.New("hsm offline") }
	if _, err := SignEddsaRdfc2022(unsecured, options, vectors.Contexts, failing); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("signer error: got %v", err)
	}
}

func TestVerifyRefusesMalformedProofs(t *testing.T) {
	vectors := loadVectors(t)
	publicKey := vectors.Holder.publicKey(t)
	base := vectors.Cases[0].Presentation
	cases := map[string]func(proof map[string]any){
		"wrong cryptosuite":      func(proof map[string]any) { proof["cryptosuite"] = "ecdsa-rdfc-2019" },
		"not multibase":          func(proof map[string]any) { proof["proofValue"] = "uAAAA" },
		"short signature":        func(proof map[string]any) { proof["proofValue"] = "z" + base58.Encode([]byte{1, 2, 3}) },
		"challenge swapped":      func(proof map[string]any) { proof["challenge"] = "another-nonce" },
		"domain swapped":         func(proof map[string]any) { proof["domain"] = "another-verifier" },
		"proof purpose swapped":  func(proof map[string]any) { proof["proofPurpose"] = ProofPurposeAssertionMethod },
		"verification method up": func(proof map[string]any) { proof["verificationMethod"] = vectors.Issuer.VerificationMethod },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			document := map[string]any{}
			for key, value := range base {
				document[key] = value
			}
			proof := map[string]any{}
			for key, value := range base["proof"].(map[string]any) {
				proof[key] = value
			}
			mutate(proof)
			document["proof"] = proof
			if err := VerifyEddsaRdfc2022(document, vectors.Contexts, publicKey); !errors.Is(err, ErrProofInvalid) {
				t.Fatalf("got %v, want ErrProofInvalid", err)
			}
		})
	}
	if err := VerifyEddsaRdfc2022(withoutProof(base), vectors.Contexts, publicKey); !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("missing proof: got %v", err)
	}
}

// blankNodeClique is a JSON-LD document of size blank nodes that all link to
// each other, so every node has the same first-degree hash: the shape that
// makes RDFC-1.0 run in factorial time.
func blankNodeClique(size int) map[string]any {
	graph := make([]any, size)
	for i := range graph {
		var links []any
		for j := 0; j < size; j++ {
			if j != i {
				links = append(links, fmt.Sprintf("_:b%d", j))
			}
		}
		graph[i] = map[string]any{"@id": fmt.Sprintf("_:b%d", i), "p": links}
	}
	return map[string]any{
		"@context": map[string]any{"p": map[string]any{"@id": "https://example.test/p", "@type": "@id"}},
		"@graph":   graph,
	}
}

func TestCanonicalizeRefusesADatasetPoisoningCliqueBeforeCanonicalizing(t *testing.T) {
	started := time.Now()
	_, err := Canonicalize(blankNodeClique(9), nil)
	if !errors.Is(err, ErrCanonicalizationTooComplex) {
		t.Fatalf("got %v, want ErrCanonicalizationTooComplex", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("refusal took %v", elapsed)
	}
	if _, err := Canonicalize(blankNodeClique(maxAmbiguousBlankNodes), nil); err != nil {
		t.Fatalf("a clique within the bound: %v", err)
	}
}

func TestCanonicalizeRefusesTooManyBlankNodes(t *testing.T) {
	graph := make([]any, maxBlankNodes+1)
	for i := range graph {
		graph[i] = map[string]any{"@id": fmt.Sprintf("_:b%d", i), "p": fmt.Sprintf("https://example.test/%d", i)}
	}
	document := map[string]any{
		"@context": map[string]any{"p": map[string]any{"@id": "https://example.test/p", "@type": "@id"}},
		"@graph":   graph,
	}
	if _, err := Canonicalize(document, nil); !errors.Is(err, ErrCanonicalizationTooComplex) {
		t.Fatalf("got %v, want ErrCanonicalizationTooComplex", err)
	}
}

func TestVerifyWithOptionsChecksTheVerifierExpectations(t *testing.T) {
	vectors := loadVectors(t)
	presentation := vectors.Cases[0].Presentation
	proof := presentation["proof"].(map[string]any)
	created, err := time.Parse(time.RFC3339Nano, proof["created"].(string))
	if err != nil {
		t.Fatal(err)
	}
	publicKey := vectors.Holder.publicKey(t)
	matching := VerifyOptions{
		ProofPurpose:       ProofPurposeAuthentication,
		VerificationMethod: vectors.Holder.VerificationMethod,
		Challenge:          proof["challenge"].(string),
		Domain:             proof["domain"].(string),
		Now:                created.Add(time.Minute),
	}
	if err := VerifyEddsaRdfc2022WithOptions(presentation, vectors.Contexts, publicKey, matching); err != nil {
		t.Fatalf("matching options: %v", err)
	}
	cases := map[string]func(o *VerifyOptions){
		"another purpose":             func(o *VerifyOptions) { o.ProofPurpose = ProofPurposeAssertionMethod },
		"another verification method": func(o *VerifyOptions) { o.VerificationMethod = vectors.Issuer.VerificationMethod },
		"another challenge":           func(o *VerifyOptions) { o.Challenge = "another-nonce" },
		"another domain":              func(o *VerifyOptions) { o.Domain = "another-verifier" },
		"created in the future":       func(o *VerifyOptions) { o.Now = created.Add(-time.Hour) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			options := matching
			mutate(&options)
			if err := VerifyEddsaRdfc2022WithOptions(presentation, vectors.Contexts, publicKey, options); !errors.Is(err, ErrProofInvalid) {
				t.Fatalf("got %v, want ErrProofInvalid", err)
			}
		})
	}
}

func withProof(document map[string]any, proof any) map[string]any {
	secured := withoutProof(document)
	secured["proof"] = proof
	return secured
}

func TestVerifyRefusesMalformedProofMembers(t *testing.T) {
	vectors := loadVectors(t)
	presentation := vectors.Cases[0].Presentation
	proof := presentation["proof"].(map[string]any)
	with := func(name string, value any) map[string]any {
		changed := map[string]any{}
		for key, member := range proof {
			changed[key] = member
		}
		changed[name] = value
		return withProof(presentation, changed)
	}
	cases := map[string]map[string]any{
		"created is not a dateTimeStamp": with("created", "2026-09-23"),
		"expires is not a string":        with("expires", 1),
		"expired":                        with("expires", "2000-01-01T00:00:00Z"),
		"chained proof":                  with("previousProof", "urn:uuid:1"),
		"no proofPurpose":                with("proofPurpose", ""),
		"empty proof set":                withProof(presentation, []any{}),
		"proof set entry not an object":  withProof(presentation, []any{"proof"}),
	}
	options := VerifyOptions{Now: time.Now()}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if err := VerifyEddsaRdfc2022WithOptions(document, vectors.Contexts, vectors.Holder.publicKey(t), options); !errors.Is(err, ErrProofInvalid) {
				t.Fatalf("got %v, want ErrProofInvalid", err)
			}
		})
	}
}

func TestVerifySelectsTheProofOfAProofSet(t *testing.T) {
	vectors := loadVectors(t)
	presentation := vectors.Cases[0].Presentation
	proof := presentation["proof"].(map[string]any)
	other := map[string]any{"type": ProofType, "cryptosuite": "ecdsa-rdfc-2019", "proofPurpose": ProofPurposeAuthentication, "verificationMethod": "did:example:other#key", "proofValue": "zabc"}
	publicKey := vectors.Holder.publicKey(t)

	set := withProof(presentation, []any{other, proof})
	if err := VerifyEddsaRdfc2022(set, vectors.Contexts, publicKey); err != nil {
		t.Fatalf("proof set: %v", err)
	}

	second := map[string]any{}
	for key, value := range proof {
		second[key] = value
	}
	second["verificationMethod"] = vectors.Issuer.VerificationMethod
	ambiguous := withProof(presentation, []any{second, proof})
	if err := VerifyEddsaRdfc2022(ambiguous, vectors.Contexts, publicKey); !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("ambiguous proof set: got %v, want ErrProofInvalid", err)
	}
	selected := VerifyOptions{VerificationMethod: vectors.Holder.VerificationMethod}
	if err := VerifyEddsaRdfc2022WithOptions(ambiguous, vectors.Contexts, publicKey, selected); err != nil {
		t.Fatalf("selected proof: %v", err)
	}
}
