package statuslist

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/internal/testutil"
)

// TestCheckBindsTheTokenToTheCredentialIssuerByKey covers
// draft-ietf-oauth-status-list-21 Section 11.3: the Status List Token is bound
// to the Referenced Token by its issuer's key, not by a claim. Section 5.1
// defines no `iss` for the token, so the keys are always resolved for the
// credential issuer, and a token signed by another issuer - however trusted,
// and whatever `iss` it states - says nothing about this credential.
func TestCheckBindsTheTokenToTheCredentialIssuerByKey(t *testing.T) {
	const issuerA = "https://issuer-a.example.test"
	const issuerB = "https://issuer-b.example.test"

	// setup serves a token signed by issuer B's key, with its claims adjusted.
	setup := func(t *testing.T, adjust func(claims map[string]any)) (*harness, *Checker, *[]string) {
		h := newHarness(t)
		keyA := testutil.NewP256Key(t)
		registry := map[string][]jose.JSONWebKey{
			issuerA: {publicJWK(keyA, "a")},
			issuerB: {publicJWK(h.key, "key-1")},
		}
		claims := defaultClaims(h.uri)
		claims["iss"] = issuerB
		if adjust != nil {
			adjust(claims)
		}
		h.serveToken(signES256(t, h.key, defaultHeader(), claims))
		var resolved []string
		checker := &Checker{
			HTTPClient: h.server.Client(),
			Now:        func() time.Time { return testNow },
			ResolveIssuerKeys: func(_ context.Context, request KeyRequest) ([]jose.JSONWebKey, error) {
				resolved = append(resolved, request.Issuer)
				return registry[request.Issuer], nil
			},
		}
		return h, checker, &resolved
	}
	status := func(h *harness) map[string]any {
		return map[string]any{"status_list": map[string]any{"uri": h.uri, "idx": 1}}
	}

	t.Run("a token without iss is verified under the credential issuer's keys", func(t *testing.T) {
		// A Section 5.1 token carries no iss.
		h, checker, resolved := setup(t, func(claims map[string]any) { delete(claims, "iss") })
		result, err := checker.Check(context.Background(), issuerB, status(h))
		if err != nil {
			t.Fatal(err)
		}
		if result.TokenIssuer != "" || result.StatusIssuer != issuerB || len(*resolved) != 1 || (*resolved)[0] != issuerB {
			t.Fatalf("TokenIssuer = %q, StatusIssuer = %q, resolved = %v", result.TokenIssuer, result.StatusIssuer, *resolved)
		}
	})

	t.Run("a token of another trusted issuer does not verify under the credential issuer's keys", func(t *testing.T) {
		h, checker, resolved := setup(t, nil)
		_, err := checker.Check(context.Background(), issuerA, status(h))
		assertSentinel(t, err, ErrStatusListSignatureInvalid)
		if len(*resolved) != 1 || (*resolved)[0] != issuerA {
			t.Fatalf("keys were resolved for %v, want only the credential issuer", *resolved)
		}
	})

	t.Run("a token without iss signed by another issuer does not verify either", func(t *testing.T) {
		h, checker, _ := setup(t, func(claims map[string]any) { delete(claims, "iss") })
		_, err := checker.Check(context.Background(), issuerA, status(h))
		assertSentinel(t, err, ErrStatusListSignatureInvalid)
	})

	t.Run("an iss naming another party does not redirect key resolution", func(t *testing.T) {
		// The token names issuer A, but it is signed by issuer B, the
		// credential issuer: the key binds it, and the claim is reported as
		// stated.
		h, checker, resolved := setup(t, func(claims map[string]any) { claims["iss"] = issuerA })
		result, err := checker.Check(context.Background(), issuerB, status(h))
		if err != nil {
			t.Fatal(err)
		}
		if result.TokenIssuer != issuerA || result.StatusIssuer != issuerB || (*resolved)[0] != issuerB {
			t.Fatalf("TokenIssuer = %q, StatusIssuer = %q, resolved = %v", result.TokenIssuer, result.StatusIssuer, *resolved)
		}
	})

	t.Run("the token of the credential issuer is checked with that issuer's keys", func(t *testing.T) {
		h, checker, resolved := setup(t, nil)
		result, err := checker.Check(context.Background(), issuerB, status(h))
		if err != nil {
			t.Fatal(err)
		}
		if result.TokenIssuer != issuerB || result.StatusIssuer != issuerB || len(*resolved) != 1 || (*resolved)[0] != issuerB {
			t.Fatalf("TokenIssuer = %q, resolved = %v", result.TokenIssuer, *resolved)
		}
	})

	t.Run("an empty credential issuer is passed to the hook, which must bind by certificate", func(t *testing.T) {
		// SD-JWT VC -19 Section 2.5: without iss, the Issuer is the subject of
		// the credential's x5c leaf; the checker does not invent one.
		h, checker, resolved := setup(t, nil)
		_, err := checker.Check(context.Background(), "", status(h))
		assertSentinel(t, err, ErrStatusListIssuerKeyUnresolved)
		if len(*resolved) != 1 || (*resolved)[0] != "" {
			t.Fatalf("resolved = %v, want the empty credential issuer", *resolved)
		}
	})

	t.Run("an accepted Status Issuer is verified under its own keys", func(t *testing.T) {
		h, checker, resolved := setup(t, nil)
		var asked [2]string
		checker.AcceptStatusIssuer = func(_ context.Context, credentialIssuer, tokenIssuer string) error {
			asked = [2]string{credentialIssuer, tokenIssuer}
			return nil
		}
		result, err := checker.Check(context.Background(), issuerA, status(h))
		if err != nil {
			t.Fatal(err)
		}
		if asked != [2]string{issuerA, issuerB} || result.TokenIssuer != issuerB || result.StatusIssuer != issuerB || (*resolved)[0] != issuerB {
			t.Fatalf("asked = %v, TokenIssuer = %q, resolved = %v", asked, result.TokenIssuer, *resolved)
		}
	})

	t.Run("the Status Issuer hook is not asked about a token without iss", func(t *testing.T) {
		h, checker, resolved := setup(t, func(claims map[string]any) { delete(claims, "iss") })
		checker.AcceptStatusIssuer = func(context.Context, string, string) error {
			t.Fatal("AcceptStatusIssuer was called")
			return nil
		}
		if _, err := checker.Check(context.Background(), issuerB, status(h)); err != nil {
			t.Fatal(err)
		}
		if (*resolved)[0] != issuerB {
			t.Fatalf("resolved = %v", *resolved)
		}
	})

	t.Run("a Status Issuer the hook refuses is a mismatch", func(t *testing.T) {
		h, checker, resolved := setup(t, nil)
		refusal := errors.New("not a delegate")
		checker.AcceptStatusIssuer = func(context.Context, string, string) error { return refusal }
		_, err := checker.Check(context.Background(), issuerA, status(h))
		assertSentinel(t, err, ErrStatusListIssuerMismatch)
		if !errors.Is(err, refusal) || len(*resolved) != 0 {
			t.Fatalf("err = %v, resolved = %v", err, *resolved)
		}
	})
}
