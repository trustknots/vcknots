package oid4vp

import (
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// draft24X509Claims is a Draft24 Authorization Request as a verifier sends it:
// the client_id_scheme parameter and a Presentation Exchange
// presentation_definition, authenticated with an x509_san_dns Client
// Identifier.
func draft24X509Claims(f *requestObjectFixture) map[string]any {
	return map[string]any{
		"client_id":        "x509_san_dns:verifier.example",
		"client_id_scheme": "x509_san_dns",
		"response_type":    "vp_token",
		"response_mode":    "direct_post",
		"response_uri":     "https://verifier.example/response",
		"nonce":            "draft24-nonce",
		"state":            "draft24-state",
		"aud":              "https://self-issued.me/v2",
		"iat":              f.now.Unix(),
		"exp":              f.now.Add(5 * time.Minute).Unix(),
		"presentation_definition": map[string]any{
			"id":                "pd-1",
			"input_descriptors": []any{map[string]any{"id": "pid"}},
		},
	}
}

func draft24RequestURI(t *testing.T, f *requestObjectFixture, claims map[string]any) string {
	t.Helper()
	return "openid4vp://authorize?" + url.Values{
		"client_id": {claims["client_id"].(string)},
		"request":   {f.sign(t, claims, nil)},
	}.Encode()
}

// TestDraft24X509SanDNSRequestObjectWithPresentationDefinition is the
// regression for an integrator that routed every signed Request Object to the Final parser: a Draft24 request that
// combines client_id_scheme=x509_san_dns with presentation_definition and a
// signed Request Object must parse on the Draft24 entrypoint, authenticated
// against the caller's RequestObjectValidationOptions trust anchors rather
// than the legacy root pool alone.
func TestDraft24X509SanDNSRequestObjectWithPresentationDefinition(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	request, err := parseDraft24ForTest(f.presenter(), draft24RequestURI(t, f, draft24X509Claims(f)))
	if err != nil {
		t.Fatalf("Draft24 x509_san_dns request with a presentation_definition was rejected: %v", err)
	}
	if request.PresentationDefinition == nil || request.PresentationDefinition.ID != "pd-1" {
		t.Fatalf("presentation_definition did not survive the Draft24 path: %#v", request.PresentationDefinition)
	}
	if request.DcqlQuery != nil {
		t.Fatal("Draft24 Presentation Exchange request must not carry a DCQL query")
	}
	proof := request.RequestObjectVerification
	if proof == nil || proof.ClientID != "x509_san_dns:verifier.example" {
		t.Fatalf("Draft24 request object was not authenticated: %+v", proof)
	}
	// The shared path records the same evidence Final records, including the
	// revocation status of every certificate below the anchor.
	if len(proof.CertificateSHA256) != 2 || proof.RevocationChecked != 1 || proof.RevocationUnadvertised != 0 {
		t.Fatalf("Draft24 authentication evidence is incomplete: %+v", proof)
	}
}

// TestDraft24X509SanDNSRequestObjectRejectsForeignTrustAnchor is the negative
// half: the same request authenticated against another verifier's anchor.
func TestDraft24X509SanDNSRequestObjectRejectsForeignTrustAnchor(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	foreign := newRequestObjectFixture(t, "verifier.example").options()
	presenter := &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &foreign}
	_, err := parseDraft24ForTest(presenter, draft24RequestURI(t, f, draft24X509Claims(f)))
	if err == nil || !strings.Contains(err.Error(), "request object certificate chain is not trusted") {
		t.Fatalf("Draft24 must reject a Request Object signed below a foreign anchor: %v", err)
	}
}

// TestDraft24RequestObjectHonoursWalletAudience proves the unified path reads
// the caller's options rather than the Draft24 defaults: the audience check is
// off while the caller names no audience, and binding once it does.
func TestDraft24RequestObjectHonoursWalletAudience(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	options := f.options()
	options.WalletAudience = []string{"https://wallet.example"}
	presenter := &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &options}

	_, err := parseDraft24ForTest(presenter, draft24RequestURI(t, f, draft24X509Claims(f)))
	if err == nil || !strings.Contains(err.Error(), "request object audience does not identify this Wallet") {
		t.Fatalf("Draft24 must apply the configured wallet audience: %v", err)
	}

	claims := draft24X509Claims(f)
	claims["aud"] = "https://wallet.example"
	if _, err := parseDraft24ForTest(presenter, draft24RequestURI(t, f, claims)); err != nil {
		t.Fatalf("Draft24 must accept the configured wallet audience: %v", err)
	}
}

// TestDraft24RequestObjectRejectsExpiredRequestObject shows the shared
// registered-claim policy, exp included, applying to a Draft 24 x509 Request
// Object.
func TestDraft24RequestObjectRejectsExpiredRequestObject(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	claims := draft24X509Claims(f)
	claims["exp"] = f.now.Add(-time.Second).Unix()
	_, err := parseDraft24ForTest(f.presenter(), draft24RequestURI(t, f, claims))
	if err == nil || !strings.Contains(err.Error(), "request object is outside its exp validity") {
		t.Fatalf("Draft24 must reject an expired Request Object: %v", err)
	}
}

// draft24ClientMetadataSignedURI is a Draft24 request whose Request Object is
// signed with the key its own client_metadata publishes: the one Draft24 path
// that is not the shared Final authentication.
func draft24ClientMetadataSignedURI(t *testing.T, f *requestObjectFixture, issuedAt time.Time, lifetime time.Duration) string {
	t.Helper()
	claims := map[string]any{
		"client_id":     "redirect_uri:https://verifier.example/response",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"response_uri":  "https://verifier.example/response",
		"nonce":         "draft24-nonce",
		"iat":           issuedAt.Unix(),
		"exp":           issuedAt.Add(lifetime).Unix(),
		"client_metadata": map[string]any{"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &f.key.PublicKey, Algorithm: "ES256", KeyID: "verifier-key"},
		}}},
		"presentation_definition": map[string]any{
			"id":                "pd-1",
			"input_descriptors": []any{map[string]any{"id": "pid"}},
		},
	}
	token := f.sign(t, claims, (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt").WithHeader("kid", "verifier-key"))
	return "openid4vp://authorize?" + url.Values{
		"client_id": {"redirect_uri:https://verifier.example/response"},
		"request":   {token},
	}.Encode()
}

// TestDraft24ClientMetadataRequestObjectUsesTheCallerClock is the regression
// for a Draft24 Request Object judged against the wall clock. A wallet that
// re-authenticates at consent the Request Object it admitted earlier passes
// the admission instant as Now; the object must be judged at that instant
// with the caller's ClockSkew, exactly as the Final path judges it.
func TestDraft24ClientMetadataRequestObjectUsesTheCallerClock(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	// Issued an hour ago with a one-minute lifetime: expired by the wall
	// clock, valid at the admission instant the caller names.
	admission := time.Now().Add(-time.Hour).Truncate(time.Second)
	uri := draft24ClientMetadataSignedURI(t, f, admission, time.Minute)
	parse := func(now time.Time, skew time.Duration) error {
		options := RequestObjectValidationOptions{Now: func() time.Time { return now }, ClockSkew: skew}
		presenter := &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &options}
		_, err := parseDraft24ForTest(presenter, uri)
		return err
	}

	if err := parse(admission.Add(30*time.Second), 0); err != nil {
		t.Fatalf("a Request Object valid at the caller's instant was refused: %v", err)
	}
	err := parse(admission.Add(2*time.Minute), 0)
	if !errors.Is(err, ErrRequestObjectExpired) {
		t.Fatalf("a Request Object past exp at the caller's instant must be refused as expired: %v", err)
	}
	if err := parse(admission.Add(2*time.Minute), 5*time.Minute); err != nil {
		t.Fatalf("the caller's ClockSkew must be applied to exp: %v", err)
	}

	// Judged at an instant before iat, the object is refused as issued in
	// the future, which this path has always done, with the skew applied.
	early := admission.Add(-time.Hour)
	if err := parse(early, 0); !errors.Is(err, ErrRequestObjectExpired) {
		t.Fatalf("a Request Object issued after the caller's instant must be refused: %v", err)
	}
	if err := parse(early, 2*time.Hour); err != nil {
		t.Fatalf("the caller's ClockSkew must be applied to iat: %v", err)
	}
}

// A Draft24 x509_hash Request Object is authenticated through the shared X.509
// path even when the caller configured only X509TrustChainRoots: the
// thumbprint names the certificate, but only the chain says it is trusted.
func TestDraft24X509HashRequiresTrustedChain(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := map[string]any{
		"aud": "https://self-issued.me/v2", "client_id": f.clientID(), "nonce": "n",
		"response_type": "vp_token", "response_mode": "direct_post",
		"response_uri":            "https://verifier.example/response",
		"presentation_definition": map[string]any{"id": "definition"},
	}
	token := f.sign(t, claims, nil)

	trusted := x509.NewCertPool()
	trusted.AddCert(f.root)
	p := &Oid4vpPresenter{HTTPClient: f.server.Client(), X509TrustChainRoots: trusted}
	request, err := parseDraft24RequestObjectForTest(p, token, f.clientID())
	if err != nil {
		t.Fatalf("a chain to the configured root must be accepted: %v", err)
	}
	if request.RequestObjectVerification == nil {
		t.Fatal("the X.509 authentication was not recorded")
	}

	other := newRequestObjectFixture(t)
	untrusted := x509.NewCertPool()
	untrusted.AddCert(other.root)
	p = &Oid4vpPresenter{HTTPClient: f.server.Client(), X509TrustChainRoots: untrusted}
	if _, err := parseDraft24RequestObjectForTest(p, token, f.clientID()); err == nil {
		t.Fatal("an x509_hash certificate outside the configured roots must be refused")
	}
}

// TestDraft24InsecureX509SanDNSBindsTheResponseEndpoint covers the
// InsecureSkipX509Verify mode, which shares the X.509 binding of the verified
// path and skips only the chain: the DNS name binds the Response URI under
// both direct_post modes.
func TestDraft24InsecureX509SanDNSBindsTheResponseEndpoint(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	p := &Oid4vpPresenter{HTTPClient: f.server.Client(), InsecureSkipX509Verify: true}
	for _, mode := range []string{"direct_post", "direct_post.jwt"} {
		t.Run(mode, func(t *testing.T) {
			claims := f.claims()
			claims["client_id"] = "x509_san_dns:verifier.example"
			claims["response_mode"] = mode
			parse := func() (*CredentialPresentationRequest, error) {
				return parseDraft24RequestObjectForTest(p, f.sign(t, claims, nil), "x509_san_dns:verifier.example")
			}
			request, err := parse()
			if err != nil {
				t.Fatal(err)
			}
			if request.RequestObjectVerification != nil {
				t.Fatal("an unverified chain must not be reported as authenticated")
			}
			claims["response_uri"] = "https://other.example/response"
			if _, err := parse(); !errors.Is(err, ErrRequestObjectClientIDMismatch) {
				t.Fatalf("endpoint host mismatch: want ErrRequestObjectClientIDMismatch, got %v", err)
			}
		})
	}
}
