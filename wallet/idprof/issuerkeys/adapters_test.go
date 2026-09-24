package issuerkeys

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
)

// The adapters are handed to hooks whose signatures the rest of the library
// fixes; these assignments fail to compile if either drifts.
var (
	_ func(issuer string, header map[string]any) ([]jose.JSONWebKey, error)                      = (&KeyLookup{}).Keys
	_ func(ctx context.Context, issuer string, header map[string]any) ([]jose.JSONWebKey, error) = (&Resolver{}).StatusListKeyFunc(Request{}, nil)
)

func TestKeyLookup(t *testing.T) {
	t.Parallel()

	t.Run("fills the request from the header and returns the candidates of the iss", func(t *testing.T) {
		t.Parallel()
		signer := newES256Key(t, "")
		didValue := didJWK(t, signer.public)
		transport := &failingTransport{}
		resolver := &Resolver{HTTPClient: &http.Client{Transport: transport}, Mechanisms: allMechanisms(), Now: fixedNow}
		lookup := resolver.NewKeyLookup(context.Background(), Request{
			CredentialFormat:   FormatJWTVCJSON,
			CredentialIssuer:   "https://issuer.example.test/issuer",
			IssuerMetadataJWKS: keySet(signer.withKeyID("metadata-key", "ES256")),
			// Overwritten by Keys.
			Issuer: "https://ignored.example.test", KeyID: "ignored",
		})

		keys, err := lookup.Keys(didValue, map[string]any{"alg": "ES256", "kid": didValue + "#0", "typ": "JWT"})
		if err != nil {
			t.Fatalf("Keys failed: %v", err)
		}
		// The metadata candidate names the Credential Issuer, not the JWT's
		// DID `iss`, so it is not returned.
		if got := keyIDs(keys); !slices.Equal(got, []string{didValue + "#0"}) {
			t.Fatalf("key IDs = %v", got)
		}
		for _, key := range keys {
			if !key.IsPublic() {
				t.Errorf("key %q is not public", key.KeyID)
			}
		}
		if transport.count() != 0 {
			t.Errorf("requests were made: %d", transport.count())
		}

		resolution := lookup.Resolution()
		if resolution == nil || lookup.Err() != nil {
			t.Fatalf("Resolution() = %v, Err() = %v", resolution, lookup.Err())
		}
		// The verified key comes back from the acceptor without its kid; the
		// thumbprint still finds its candidate.
		bare := jose.JSONWebKey{Key: signer.public.Key}
		candidate, ok := resolution.CandidateFor(bare)
		if !ok || candidate.Mechanism != MechanismDIDMetadataBinding || candidate.DID != didValue {
			t.Errorf("CandidateFor = %+v, %v", candidate, ok)
		}
		if _, ok := resolution.CandidateFor(newES256Key(t, "").public); ok {
			t.Errorf("CandidateFor found a key the ladder never produced")
		}
	})

	t.Run("reads an x5c header decoded as a generic JSON array", func(t *testing.T) {
		t.Parallel()
		ca := newTestCA(t, "root")
		leaf := newTestLeaf(t, ca, "issuer.example.test")
		resolver := &Resolver{HTTPClient: &http.Client{Transport: &failingTransport{}}, Mechanisms: Mechanisms{X5C: true, IssuerMetadataJWKS: true}}
		lookup := resolver.NewKeyLookup(context.Background(), Request{
			CredentialFormat:   FormatSDJWTVC,
			CredentialIssuer:   "https://issuer.example.test",
			IssuerMetadataJWKS: keySet(leafJWK(leaf, "leaf")),
		})
		header := map[string]any{"alg": "ES256", "x5c": []any{x5cOf(leaf)[0]}}
		keys, err := lookup.Keys("https://issuer.example.test", header)
		if err != nil {
			t.Fatalf("Keys failed: %v", err)
		}
		if got := mechanismsOf(lookup.Resolution().Candidates); !slices.Equal(got, []Mechanism{MechanismX5CMetadataJWKSBinding, MechanismCredentialIssuerMetadataJWKS}) {
			t.Errorf("mechanisms = %v", got)
		}
		if len(keys) != 2 || lookup.Resolution().IssuerDNSName != "issuer.example.test" {
			t.Errorf("keys = %d, DNS name = %q", len(keys), lookup.Resolution().IssuerDNSName)
		}
	})

	t.Run("keeps the diagnostics of a resolution that found nothing", func(t *testing.T) {
		t.Parallel()
		resolver := &Resolver{HTTPClient: &http.Client{Transport: &failingTransport{}}, Mechanisms: Mechanisms{}}
		lookup := resolver.NewKeyLookup(context.Background(), Request{CredentialFormat: FormatSDJWTVC, CredentialIssuer: "https://issuer.example.test"})
		keys, err := lookup.Keys("https://issuer.example.test", map[string]any{"alg": "ES256"})
		if keys != nil || !errors.Is(err, ErrNoIssuerKeyResolved) || !errors.Is(lookup.Err(), ErrNoIssuerKeyResolved) {
			t.Fatalf("Keys = %v, %v; Err() = %v", keys, err, lookup.Err())
		}
		if got := len(lookup.Resolution().Diagnostics); got != 4 {
			t.Errorf("diagnostics = %d, want 4", got)
		}
	})

	t.Run("reports DID-only trust as its own error", func(t *testing.T) {
		t.Parallel()
		signer := newES256Key(t, "")
		didValue := didJWK(t, signer.public)
		resolver := &Resolver{HTTPClient: &http.Client{Transport: &failingTransport{}}, Mechanisms: Mechanisms{DIDJWK: true}}
		lookup := resolver.NewKeyLookup(context.Background(), Request{CredentialFormat: FormatJWTVCJSON, CredentialIssuer: "https://issuer.example.test"})
		_, err := lookup.Keys(didValue, map[string]any{"alg": "ES256", "kid": didValue + "#0"})
		if !errors.Is(err, ErrDIDOnlyTrustUnsupported) {
			t.Fatalf("Keys error = %v, want ErrDIDOnlyTrustUnsupported", err)
		}
		diagnostic := diagnosticFor(t, lookup.Resolution().Diagnostics, RungDID)
		if want := []string{SwitchIssuerMetadataJWKS, SwitchCredentialIssuerBinding, SwitchDIDConfiguration}; !slices.Equal(diagnostic.DisabledBy, want) {
			t.Errorf("DisabledBy = %v, want %v", diagnostic.DisabledBy, want)
		}
	})
}

// statusListFixture is an issuer that signs Status List Tokens under an https
// identifier, with a CA that certifies its signing key.
type statusListFixture struct {
	issuer   string
	ca       testCertificate
	leaf     testCertificate
	metadata testKey
	resolver *Resolver
	network  *failingTransport
}

func newStatusListFixture(t *testing.T) *statusListFixture {
	t.Helper()
	ca := newTestCA(t, "status list root")
	network := &failingTransport{}
	return &statusListFixture{
		issuer:   "https://issuer.example.test",
		ca:       ca,
		leaf:     newTestLeaf(t, ca, "issuer.example.test"),
		metadata: newES256Key(t, "metadata-key"),
		network:  network,
		resolver: &Resolver{
			HTTPClient: &http.Client{Transport: network},
			Mechanisms: Mechanisms{X5C: true, IssuerMetadataJWKS: true, DIDJWK: true},
			Now:        fixedNow,
		},
	}
}

func (f *statusListFixture) template() Request {
	return Request{
		CredentialFormat:   FormatJWTVCJSON,
		CredentialIssuer:   f.issuer,
		IssuerMetadataJWKS: keySet(f.metadata.public),
	}
}

func (f *statusListFixture) trust(anchors ...*x509.Certificate) *X5CTrust {
	return &X5CTrust{TrustAnchors: anchors, AllowUnadvertisedRevocation: true}
}

func (f *statusListFixture) header(leaf testCertificate) map[string]any {
	chain := x5cOf(leaf)
	values := make([]any, 0, len(chain))
	for _, value := range chain {
		values = append(values, value)
	}
	return map[string]any{"alg": "ES256", "typ": "statuslist+jwt", "x5c": values}
}

func TestStatusListKeys(t *testing.T) {
	t.Parallel()

	t.Run("a trusted chain puts the leaf key first, then the ladder", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		keys, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), f.trust(f.ca.certificate), f.issuer, f.header(f.leaf))
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismX5CTrustedChain, MechanismCredentialIssuerMetadataJWKS}) {
			t.Fatalf("mechanisms = %v", got)
		}
		if len(keys) != 2 || !keys[0].IsPublic() {
			t.Fatalf("keys = %+v", keys)
		}
		trusted, ok := resolution.CandidateFor(jose.JSONWebKey{Key: f.leaf.certificate.PublicKey})
		if !ok || trusted.Mechanism != MechanismX5CTrustedChain || trusted.Issuer != f.issuer || len(trusted.CertificateSHA256) != 2 {
			t.Errorf("trusted candidate = %+v, %v", trusted, ok)
		}
		if f.network.count() != 0 {
			t.Errorf("requests were made: %d", f.network.count())
		}
	})

	t.Run("a chain reaching no configured anchor is recorded and the ladder continues", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		other := newTestCA(t, "other root")
		keys, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), f.trust(other.certificate), f.issuer, f.header(f.leaf))
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismCredentialIssuerMetadataJWKS}) || len(keys) != 1 {
			t.Fatalf("mechanisms = %v", got)
		}
		diagnostic := diagnosticFor(t, resolution.Diagnostics, RungX5C)
		if diagnostic.Failure != failureChainUntrusted || diagnostic.Attempted || diagnostic.CandidateCount != 0 {
			t.Errorf("x5c diagnostic = %+v", diagnostic)
		}
	})

	t.Run("an untrusted chain and nothing else is an unresolved error naming the chain", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		template := f.template()
		template.IssuerMetadataJWKS = nil
		_, _, err := f.resolver.StatusListKeys(context.Background(), template, f.trust(), f.issuer, f.header(f.leaf))
		var unresolved *UnresolvedError
		if !errors.As(err, &unresolved) {
			t.Fatalf("StatusListKeys error = %v, want *UnresolvedError", err)
		}
		if got := diagnosticFor(t, unresolved.Diagnostics, RungX5C).Failure; got != failureChainUntrusted {
			t.Errorf("x5c failure = %q", got)
		}
	})

	t.Run("a leaf that does not name the issuer host is not trusted", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		stranger := newTestLeaf(t, f.ca, "other.example.test")
		_, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), f.trust(f.ca.certificate), f.issuer, f.header(stranger))
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismCredentialIssuerMetadataJWKS}) {
			t.Errorf("mechanisms = %v", got)
		}
		if got := diagnosticFor(t, resolution.Diagnostics, RungX5C).Failure; got != failureChainUntrusted {
			t.Errorf("x5c failure = %q", got)
		}
	})

	t.Run("a revocation status that cannot be established ends the verification", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		trust := f.trust(f.ca.certificate)
		trust.AllowUnadvertisedRevocation = false
		keys, _, err := f.resolver.StatusListKeys(context.Background(), f.template(), trust, f.issuer, f.header(f.leaf))
		if err == nil || keys != nil {
			t.Fatalf("StatusListKeys = %v, %v; want the chain refusal", keys, err)
		}
		if errors.Is(err, ErrNoIssuerKeyResolved) {
			t.Fatalf("a revocation refusal fell through to the ladder: %v", err)
		}
		if code, _ := common.CodeOf(err); code != "x509_chain_revocation_unknown" {
			t.Errorf("code = %q, want x509_chain_revocation_unknown", code)
		}
	})

	t.Run("only ladder candidates resolved for the token's iss are offered", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		didValue := didJWK(t, f.metadata.public)
		header := map[string]any{"alg": "ES256", "kid": didValue + "#0"}
		keys, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), nil, f.issuer, header)
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		// The DID rung bound the key through the metadata, but under the DID,
		// which is not this token's iss; the metadata candidate is.
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismCredentialIssuerMetadataJWKS}) || len(keys) != 1 {
			t.Fatalf("mechanisms = %v", got)
		}
		candidate, ok := resolution.CandidateFor(keys[0])
		if !ok || candidate.Mechanism != MechanismCredentialIssuerMetadataJWKS {
			t.Errorf("CandidateFor = %+v, %v", candidate, ok)
		}
	})

	t.Run("a token signed under a DID iss is offered the DID candidate only", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		didValue := didJWK(t, f.metadata.public)
		keys, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), nil, didValue, map[string]any{"alg": "ES256", "kid": didValue + "#0"})
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismDIDMetadataBinding}) || len(keys) != 1 {
			t.Fatalf("mechanisms = %v", got)
		}
	})

	t.Run("without x5c trust the chain is never walked", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		_, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), nil, f.issuer, f.header(f.leaf))
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismCredentialIssuerMetadataJWKS}) {
			t.Errorf("mechanisms = %v", got)
		}
		if diagnostic := diagnosticFor(t, resolution.Diagnostics, RungX5C); diagnostic.Failure != "" || !diagnostic.Attempted {
			t.Errorf("x5c diagnostic = %+v, want the untouched rung result", diagnostic)
		}
	})

	t.Run("the x5c rung switched off leaves the chain unwalked", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		f.resolver.Mechanisms.X5C = false
		_, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), f.trust(f.ca.certificate), f.issuer, f.header(f.leaf))
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismCredentialIssuerMetadataJWKS}) {
			t.Errorf("mechanisms = %v", got)
		}
	})

	t.Run("a private metadata key is returned as its public half", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		template := f.template()
		template.IssuerMetadataJWKS = keySet(jose.JSONWebKey{Key: f.metadata.private, KeyID: "metadata-key"})
		keys, err := f.resolver.StatusListKeyFunc(template, nil)(context.Background(), f.issuer, map[string]any{"alg": "ES256"})
		if err != nil {
			t.Fatalf("StatusListKeyFunc failed: %v", err)
		}
		if len(keys) != 1 || !keys[0].IsPublic() || keys[0].KeyID != "metadata-key" {
			t.Errorf("keys = %+v", keys)
		}
	})
}

func keyIDs(keys []jose.JSONWebKey) []string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.KeyID)
	}
	return ids
}
