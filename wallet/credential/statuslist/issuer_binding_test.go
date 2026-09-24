package statuslist

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/internal/testutil"
)

// TestCheckBindsTheTokenIssuerToTheCredentialIssuer covers a key registry that
// trusts two issuers: a Status List Token signed by one of them must not decide
// the status of a credential issued by the other.
func TestCheckBindsTheTokenIssuerToTheCredentialIssuer(t *testing.T) {
	const issuerA = "https://issuer-a.example.test"
	const issuerB = "https://issuer-b.example.test"

	setup := func(t *testing.T) (*harness, *Checker, *[]string) {
		h := newHarness(t)
		keyA := testutil.NewP256Key(t)
		registry := map[string][]jose.JSONWebKey{
			issuerA: {publicJWK(keyA, "a")},
			issuerB: {publicJWK(h.key, "key-1")},
		}
		claims := defaultClaims(h.uri)
		claims["iss"] = issuerB
		h.serveToken(signES256(t, h.key, defaultHeader(), claims))
		var resolved []string
		checker := &Checker{
			HTTPClient: h.server.Client(),
			Now:        func() time.Time { return testNow },
			ResolveIssuerKeys: func(_ context.Context, issuer string, _ map[string]any) ([]jose.JSONWebKey, error) {
				resolved = append(resolved, issuer)
				return registry[issuer], nil
			},
		}
		return h, checker, &resolved
	}
	status := func(h *harness) map[string]any {
		return map[string]any{"status_list": map[string]any{"uri": h.uri, "idx": 1}}
	}

	t.Run("a token of another trusted issuer is refused before any key is resolved", func(t *testing.T) {
		h, checker, resolved := setup(t)
		_, err := checker.Check(context.Background(), issuerA, status(h))
		assertSentinel(t, err, ErrStatusListIssuerMismatch)
		if len(*resolved) != 0 {
			t.Fatalf("keys were resolved for %v", *resolved)
		}
	})

	t.Run("the token of the credential issuer is checked with that issuer's keys", func(t *testing.T) {
		h, checker, resolved := setup(t)
		result, err := checker.Check(context.Background(), issuerB, status(h))
		if err != nil {
			t.Fatal(err)
		}
		if result.TokenIssuer != issuerB || len(*resolved) != 1 || (*resolved)[0] != issuerB {
			t.Fatalf("TokenIssuer = %q, resolved = %v", result.TokenIssuer, *resolved)
		}
	})

	t.Run("an empty credential issuer is refused", func(t *testing.T) {
		h, checker, _ := setup(t)
		_, err := checker.Check(context.Background(), "", status(h))
		assertSentinel(t, err, ErrStatusListIssuerMismatch)
		if h.requests.Load() != 0 {
			t.Fatal("the status list was fetched")
		}
	})

	t.Run("an accepted Status Issuer is verified under its own keys", func(t *testing.T) {
		h, checker, resolved := setup(t)
		var asked [2]string
		checker.AcceptStatusIssuer = func(_ context.Context, credentialIssuer, tokenIssuer string) error {
			asked = [2]string{credentialIssuer, tokenIssuer}
			return nil
		}
		result, err := checker.Check(context.Background(), issuerA, status(h))
		if err != nil {
			t.Fatal(err)
		}
		if asked != [2]string{issuerA, issuerB} || result.TokenIssuer != issuerB || (*resolved)[0] != issuerB {
			t.Fatalf("asked = %v, TokenIssuer = %q, resolved = %v", asked, result.TokenIssuer, *resolved)
		}
	})

	t.Run("a Status Issuer the hook refuses is a mismatch", func(t *testing.T) {
		h, checker, resolved := setup(t)
		refusal := errors.New("not a delegate")
		checker.AcceptStatusIssuer = func(context.Context, string, string) error { return refusal }
		_, err := checker.Check(context.Background(), issuerA, status(h))
		assertSentinel(t, err, ErrStatusListIssuerMismatch)
		if !errors.Is(err, refusal) || len(*resolved) != 0 {
			t.Fatalf("err = %v, resolved = %v", err, *resolved)
		}
	})
}
