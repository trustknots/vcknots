package statuslist

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
)

const (
	testIssuer   = "https://issuer.example.test/issuer"
	testIssuedAt = 1_768_000_000
	testExpires  = 1_799_000_000
	statusPath   = "/status/1"
)

var testNow = time.Unix(1_779_000_000, 0).UTC()

// --- token construction ----------------------------------------------------

func publicJWK(key *ecdsa.PrivateKey, kid string) jose.JSONWebKey {
	return jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
}

func encodeSegment(t *testing.T, value any) string {
	t.Helper()
	if raw, isRaw := value.(string); isRaw {
		return base64.RawURLEncoding.EncodeToString([]byte(raw))
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// signES256 builds a compact JWS by hand so that tests control every header
// member, including ones a JOSE library would refuse to emit. A string header
// or payload is used verbatim as JSON text.
func signES256(t *testing.T, key *ecdsa.PrivateKey, header, payload any) string {
	t.Helper()
	input := encodeSegment(t, header) + "." + encodeSegment(t, payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signHS256(t *testing.T, secret []byte, header, payload any) string {
	t.Helper()
	input := encodeSegment(t, header) + "." + encodeSegment(t, payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func defaultHeader() map[string]any {
	return map[string]any{"alg": "ES256", "typ": "statuslist+jwt", "kid": "key-1"}
}

func defaultClaims(subject string) map[string]any {
	return map[string]any{
		"iss": testIssuer,
		"sub": subject,
		"iat": testIssuedAt,
		"exp": testExpires,
		"status_list": map[string]any{
			"bits": 1,
			"lst":  ietfOneBitList,
		},
	}
}

// --- server and checker ----------------------------------------------------

type served struct {
	body        string
	contentType string
	status      int
}

type harness struct {
	server    *httptest.Server
	uri       string
	key       *ecdsa.PrivateKey
	requests  atomic.Int32
	hookCalls atomic.Int32
	hookIss   atomic.Value
	hookHdr   atomic.Value
	lastReq   atomic.Value
	respond   func(w http.ResponseWriter, r *http.Request)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{key: testutil.NewP256Key(t)}
	h.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.requests.Add(1)
		h.lastReq.Store(r.Clone(context.Background()))
		h.respond(w, r)
	}))
	t.Cleanup(h.server.Close)
	h.uri = h.server.URL + statusPath
	return h
}

func (h *harness) serve(response served) {
	h.respond = func(w http.ResponseWriter, _ *http.Request) {
		if response.contentType != "" {
			w.Header().Set("Content-Type", response.contentType)
		}
		if response.status != 0 {
			w.WriteHeader(response.status)
		}
		_, _ = w.Write([]byte(response.body))
	}
}

func (h *harness) serveToken(token string) {
	h.serve(served{body: token, contentType: statusListTokenMediaType})
}

func (h *harness) checker(keys ...jose.JSONWebKey) *Checker {
	if keys == nil {
		keys = []jose.JSONWebKey{publicJWK(h.key, "key-1")}
	}
	return &Checker{
		HTTPClient: h.server.Client(),
		Now:        func() time.Time { return testNow },
		ResolveIssuerKeys: func(_ context.Context, issuer string, header map[string]any) ([]jose.JSONWebKey, error) {
			h.hookCalls.Add(1)
			h.hookIss.Store(issuer)
			h.hookHdr.Store(header)
			return keys, nil
		},
	}
}

func (h *harness) reference(index int) Reference {
	return Reference{URI: h.uri, Index: index}
}

func assertSentinel(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	wantCode := want.(common.CodedError).ErrorCode()
	if code, ok := common.CodeOf(err); !ok || code != wantCode {
		t.Fatalf("CodeOf(err) = %q, %v; want %q", code, ok, wantCode)
	}
}

// --- success paths ---------------------------------------------------------

func TestCheckReferenceReportsTheVerifiedEntryAndItsEvidence(t *testing.T) {
	h := newHarness(t)
	claims := defaultClaims(h.uri)
	claims["ttl"] = 43200
	token := signES256(t, h.key, defaultHeader(), claims)
	// Served with a trailing newline: the trimmed token is what is digested.
	h.serveToken(token + "\n")

	status, err := h.checker().CheckReference(context.Background(), testIssuer, h.reference(1))
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte(token))
	want := Status{
		URI:            h.uri,
		Index:          1,
		Bits:           1,
		Value:          0,
		TokenIssuer:    testIssuer,
		TokenSubject:   h.uri,
		TokenSHA256:    base64.RawURLEncoding.EncodeToString(digest[:]),
		TokenIssuedAt:  time.Unix(testIssuedAt, 0).UTC(),
		TokenExpiresAt: time.Unix(testExpires, 0).UTC(),
		TTLSeconds:     43200,
		IssuerKeyID:    "key-1",
		CheckedAt:      testNow,
	}
	if *status != want {
		t.Fatalf("status = %+v\nwant     %+v", *status, want)
	}

	request := h.lastReq.Load().(*http.Request)
	if request.Method != http.MethodGet || request.URL.Path != statusPath {
		t.Fatalf("request = %s %s", request.Method, request.URL.Path)
	}
	if accept := request.Header.Get("Accept"); accept != statusListTokenMediaType {
		t.Fatalf("Accept = %q", accept)
	}
	if issuer := h.hookIss.Load(); issuer != testIssuer {
		t.Fatalf("hook issuer = %v", issuer)
	}
	if header := h.hookHdr.Load().(map[string]any); header["typ"] != statusListTokenType || header["kid"] != "key-1" {
		t.Fatalf("hook header = %v", header)
	}
}

func TestCheckReadsEveryIndexOfTheIETFExample(t *testing.T) {
	h := newHarness(t)
	h.serveToken(signES256(t, h.key, defaultHeader(), defaultClaims(h.uri)))
	checker := h.checker()
	want := []int{1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1}
	for index, value := range want {
		// idx as a json.Number, as a UseNumber decoder produces it.
		status, err := checker.Check(context.Background(), testIssuer, map[string]any{
			"status_list": map[string]any{"idx": json.Number(fmt.Sprint(index)), "uri": h.uri},
		})
		if err != nil {
			t.Fatalf("index %d: %v", index, err)
		}
		if status.Value != value {
			t.Fatalf("index %d: value = %d, want %d", index, status.Value, value)
		}
	}
	_, err := checker.Check(context.Background(), testIssuer, map[string]any{
		"status_list": map[string]any{"idx": float64(16), "uri": h.uri},
	})
	assertSentinel(t, err, ErrStatusListIndexOutOfRange)
}

func TestCheckReferenceReadsMultiBitLists(t *testing.T) {
	for _, test := range []struct {
		bits  int
		raw   []byte
		index int
		want  int
	}{
		{2, []byte{0xC9, 0x44, 0xF9}, 0, 1},
		{2, []byte{0xC9, 0x44, 0xF9}, 3, 3},
		{4, []byte{0x21, 0xF0}, 3, 15},
		{8, []byte{0x00, 0x02}, 1, 2},
	} {
		t.Run(fmt.Sprintf("bits=%d index=%d", test.bits, test.index), func(t *testing.T) {
			h := newHarness(t)
			claims := defaultClaims(h.uri)
			claims["status_list"] = map[string]any{"bits": test.bits, "lst": zlibList(t, test.raw)}
			h.serveToken(signES256(t, h.key, defaultHeader(), claims))
			status, err := h.checker().CheckReference(context.Background(), testIssuer, h.reference(test.index))
			if err != nil {
				t.Fatal(err)
			}
			if status.Value != test.want || status.Bits != test.bits {
				t.Fatalf("value = %d bits = %d, want %d bits %d", status.Value, status.Bits, test.want, test.bits)
			}
		})
	}
}

func TestCheckReferenceAcceptsOptionalClaimVariants(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(claims map[string]any)
		skew   time.Duration
		check  func(t *testing.T, status *Status)
	}{
		{
			name:   "fractional ttl",
			mutate: func(c map[string]any) { c["ttl"] = 0.5 },
			check: func(t *testing.T, s *Status) {
				if s.TTLSeconds != 0.5 {
					t.Fatalf("TTLSeconds = %v", s.TTLSeconds)
				}
			},
		},
		{
			name:   "no exp",
			mutate: func(c map[string]any) { delete(c, "exp") },
			check: func(t *testing.T, s *Status) {
				if !s.TokenExpiresAt.IsZero() || s.TTLSeconds != 0 {
					t.Fatalf("TokenExpiresAt = %v TTLSeconds = %v", s.TokenExpiresAt, s.TTLSeconds)
				}
			},
		},
		{
			name:   "exp passed but within clock skew",
			mutate: func(c map[string]any) { c["exp"] = testNow.Unix() - 30 },
			skew:   time.Minute,
		},
		{
			name:   "nbf in the past",
			mutate: func(c map[string]any) { c["nbf"] = testIssuedAt },
		},
		{
			name:   "nbf in the future but within clock skew",
			mutate: func(c map[string]any) { c["nbf"] = testNow.Unix() + 30 },
			skew:   time.Minute,
		},
		{
			name:   "fractional iat",
			mutate: func(c map[string]any) { c["iat"] = 1_768_000_000.25 },
			check: func(t *testing.T, s *Status) {
				if want := time.Unix(testIssuedAt, 250_000_000).UTC(); !s.TokenIssuedAt.Equal(want) {
					t.Fatalf("TokenIssuedAt = %v, want %v", s.TokenIssuedAt, want)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			claims := defaultClaims(h.uri)
			test.mutate(claims)
			h.serveToken(signES256(t, h.key, defaultHeader(), claims))
			checker := h.checker()
			checker.ClockSkew = test.skew
			status, err := checker.CheckReference(context.Background(), testIssuer, h.reference(1))
			if err != nil {
				t.Fatal(err)
			}
			if test.check != nil {
				test.check(t, status)
			}
		})
	}
}

func TestCheckReferenceAcceptsMediaTypeParameters(t *testing.T) {
	h := newHarness(t)
	h.serve(served{
		body:        signES256(t, h.key, defaultHeader(), defaultClaims(h.uri)),
		contentType: "Application/StatusList+JWT; charset=utf-8",
	})
	if _, err := h.checker().CheckReference(context.Background(), testIssuer, h.reference(1)); err != nil {
		t.Fatal(err)
	}
}

func TestCheckReferenceUsesTheKidOnlyAsAHint(t *testing.T) {
	signer := testutil.NewP256Key(t)
	other := testutil.NewP256Key(t)
	tests := []struct {
		name      string
		headerKid any // nil means no kid header
		keys      []jose.JSONWebKey
		wantKeyID string
		wantErr   error
	}{
		{
			name:      "kid names the verifying key among others",
			headerKid: "key-1",
			keys:      []jose.JSONWebKey{publicJWK(other, "key-2"), publicJWK(signer, "key-1")},
			wantKeyID: "key-1",
		},
		{
			name:      "kid names no resolved key, every key is tried",
			headerKid: "rotated-away",
			keys:      []jose.JSONWebKey{publicJWK(other, "key-2"), publicJWK(signer, "key-1")},
			wantKeyID: "key-1",
		},
		{
			name:      "no kid header, every key is tried",
			keys:      []jose.JSONWebKey{publicJWK(other, "key-2"), publicJWK(signer, "key-3")},
			wantKeyID: "key-3",
		},
		{
			name:      "key id is read from the key, not the header",
			headerKid: "claimed-by-header",
			keys:      []jose.JSONWebKey{{Key: &signer.PublicKey}},
			wantKeyID: "",
		},
		{
			name:      "a kid naming a key that does not verify still lets the other keys be tried",
			headerKid: "key-2",
			keys:      []jose.JSONWebKey{publicJWK(other, "key-2"), publicJWK(signer, "key-1")},
			wantKeyID: "key-1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			header := defaultHeader()
			delete(header, "kid")
			if test.headerKid != nil {
				header["kid"] = test.headerKid
			}
			h.serveToken(signES256(t, signer, header, defaultClaims(h.uri)))
			status, err := h.checker(test.keys...).CheckReference(context.Background(), testIssuer, h.reference(0))
			if test.wantErr != nil {
				assertSentinel(t, err, test.wantErr)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if status.IssuerKeyID != test.wantKeyID {
				t.Fatalf("IssuerKeyID = %q, want %q", status.IssuerKeyID, test.wantKeyID)
			}
		})
	}
}

// --- failure paths ---------------------------------------------------------

type failureCase struct {
	name string
	// token builds the served token; nil means a valid default token.
	token func(t *testing.T, h *harness) string
	// respond overrides the server's answer entirely.
	respond func(t *testing.T, h *harness) func(http.ResponseWriter, *http.Request)
	// configure adjusts the checker.
	configure func(h *harness, c *Checker)
	uri       func(h *harness) string
	index     int
	want      error
	// hookMustNotRun asserts the key resolution hook was never called.
	hookMustNotRun bool
	// fetchMustNotRun asserts the endpoint was never requested.
	fetchMustNotRun bool
	// wantMessage, when set, must appear in the error text; it tells apart
	// two paths that report the same sentinel.
	wantMessage string
}

func tokenWith(mutateHeader func(map[string]any), mutateClaims func(map[string]any)) func(*testing.T, *harness) string {
	return func(t *testing.T, h *harness) string {
		header := defaultHeader()
		claims := defaultClaims(h.uri)
		if mutateHeader != nil {
			mutateHeader(header)
		}
		if mutateClaims != nil {
			mutateClaims(claims)
		}
		return signES256(t, h.key, header, claims)
	}
}

func claimsWith(mutate func(map[string]any)) func(*testing.T, *harness) string {
	return tokenWith(nil, mutate)
}

func runFailureCases(t *testing.T, cases []failureCase) {
	t.Helper()
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			switch {
			case test.respond != nil:
				h.respond = test.respond(t, h)
			case test.token != nil:
				h.serveToken(test.token(t, h))
			default:
				h.serveToken(signES256(t, h.key, defaultHeader(), defaultClaims(h.uri)))
			}
			checker := h.checker()
			if test.configure != nil {
				test.configure(h, checker)
			}
			reference := h.reference(test.index)
			if test.uri != nil {
				reference.URI = test.uri(h)
			}
			status, err := checker.CheckReference(context.Background(), testIssuer, reference)
			if status != nil {
				t.Fatalf("status = %+v, want nil", status)
			}
			assertSentinel(t, err, test.want)
			if test.wantMessage != "" && !strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("err = %v, want it to mention %q", err, test.wantMessage)
			}
			if test.hookMustNotRun && h.hookCalls.Load() != 0 {
				t.Fatalf("key resolution hook ran %d times", h.hookCalls.Load())
			}
			if test.fetchMustNotRun && h.requests.Load() != 0 {
				t.Fatalf("endpoint was requested %d times", h.requests.Load())
			}
		})
	}
}

func TestCheckReferenceRefusesUnusableReferences(t *testing.T) {
	uri := func(raw string) func(*harness) string { return func(*harness) string { return raw } }
	runFailureCases(t, []failureCase{
		{name: "not a URL", uri: uri("not a valid URL"), want: ErrStatusReferenceInvalid, fetchMustNotRun: true},
		{name: "empty", uri: uri(""), want: ErrStatusReferenceInvalid, fetchMustNotRun: true},
		{name: "relative", uri: uri("/status/1"), want: ErrStatusReferenceInvalid, fetchMustNotRun: true},
		{name: "http without AllowHTTP", uri: func(h *harness) string {
			return strings.Replace(h.uri, "https://", "http://", 1)
		}, want: ErrStatusReferenceInvalid, fetchMustNotRun: true},
		{name: "other scheme", uri: uri("ftp://issuer.example.test/status"), want: ErrStatusReferenceInvalid, fetchMustNotRun: true},
		{name: "query", uri: func(h *harness) string { return h.uri + "?page=1" }, want: ErrStatusReferenceInvalid, fetchMustNotRun: true},
		{name: "empty query", uri: func(h *harness) string { return h.uri + "?" }, want: ErrStatusReferenceInvalid, fetchMustNotRun: true},
		{name: "fragment", uri: func(h *harness) string { return h.uri + "#x" }, want: ErrStatusReferenceInvalid, fetchMustNotRun: true},
		{name: "user information", uri: func(h *harness) string {
			return strings.Replace(h.uri, "https://", "https://user:pass@", 1)
		}, want: ErrStatusReferenceInvalid, fetchMustNotRun: true},
		{name: "negative index", index: -1, want: ErrStatusReferenceInvalid, fetchMustNotRun: true},
	})
}

func TestCheckReferenceRefusesFailedFetches(t *testing.T) {
	respondWith := func(response served) func(*testing.T, *harness) func(http.ResponseWriter, *http.Request) {
		return func(_ *testing.T, h *harness) func(http.ResponseWriter, *http.Request) {
			h.serve(response)
			return h.respond
		}
	}
	var redirectTargetHits atomic.Int32
	runFailureCases(t, []failureCase{
		{
			name: "redirect to a valid token is not followed",
			respond: func(t *testing.T, h *harness) func(http.ResponseWriter, *http.Request) {
				token := signES256(t, h.key, defaultHeader(), defaultClaims(h.uri))
				return func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/moved" {
						redirectTargetHits.Add(1)
						w.Header().Set("Content-Type", statusListTokenMediaType)
						_, _ = w.Write([]byte(token))
						return
					}
					http.Redirect(w, r, "/moved", http.StatusFound)
				}
			},
			want:           ErrStatusListFetchFailed,
			wantMessage:    "redirect status 302",
			hookMustNotRun: true,
		},
		{name: "server error", respond: respondWith(served{status: 500, contentType: statusListTokenMediaType, body: "x"}), want: ErrStatusListFetchFailed, hookMustNotRun: true},
		{name: "not found", respond: respondWith(served{status: 404, contentType: statusListTokenMediaType}), want: ErrStatusListFetchFailed, hookMustNotRun: true},
		{name: "json content type", respond: respondWith(served{contentType: "application/json", body: "not-a-jwt"}), want: ErrStatusListFetchFailed, hookMustNotRun: true},
		{name: "plain jwt content type", respond: respondWith(served{contentType: "application/jwt", body: "a.b.c"}), want: ErrStatusListFetchFailed, hookMustNotRun: true},
		{name: "media type prefix only", respond: respondWith(served{contentType: "application/statuslist+jwtx", body: "a.b.c"}), want: ErrStatusListFetchFailed, hookMustNotRun: true},
		{name: "empty body", respond: respondWith(served{contentType: statusListTokenMediaType}), want: ErrStatusListFetchFailed, hookMustNotRun: true},
		{name: "whitespace body", respond: respondWith(served{contentType: statusListTokenMediaType, body: " \n"}), want: ErrStatusListFetchFailed, hookMustNotRun: true},
		{
			name: "declared length over the cap",
			respond: func(t *testing.T, h *harness) func(http.ResponseWriter, *http.Request) {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", statusListTokenMediaType)
					w.Header().Set("Content-Length", "2048")
					_, _ = w.Write(make([]byte, 2048))
				}
			},
			configure:      func(_ *harness, c *Checker) { c.MaxTokenBytes = 1024 },
			want:           ErrStatusListFetchFailed,
			wantMessage:    "2048 bytes declared, limit 1024",
			hookMustNotRun: true,
		},
		{
			name: "undeclared chunked body over the cap",
			respond: func(t *testing.T, h *harness) func(http.ResponseWriter, *http.Request) {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", statusListTokenMediaType)
					for range 8 {
						_, _ = w.Write([]byte(strings.Repeat("a", 512)))
						w.(http.Flusher).Flush()
					}
				}
			},
			configure:      func(_ *harness, c *Checker) { c.MaxTokenBytes = 1024 },
			want:           ErrStatusListFetchFailed,
			wantMessage:    "exceeds the size limit: limit 1024",
			hookMustNotRun: true,
		},
		{
			name: "undeclared body over the default cap",
			respond: func(t *testing.T, h *harness) func(http.ResponseWriter, *http.Request) {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", statusListTokenMediaType)
					w.(http.Flusher).Flush()
					_, _ = w.Write(make([]byte, httpfetch.DefaultBodyLimit+1))
				}
			},
			want:           ErrStatusListFetchFailed,
			hookMustNotRun: true,
		},
		{
			name:           "unreachable endpoint",
			configure:      func(h *harness, _ *Checker) { h.server.Close() },
			want:           ErrStatusListFetchFailed,
			hookMustNotRun: true,
		},
	})
	if hits := redirectTargetHits.Load(); hits != 0 {
		t.Fatalf("redirect target was requested %d times", hits)
	}
}

func TestCheckReferenceRefusesTokensBeforeResolvingKeys(t *testing.T) {
	runFailureCases(t, []failureCase{
		{name: "typ JWT", token: tokenWith(func(h map[string]any) { h["typ"] = "JWT" }, nil), want: ErrStatusListTokenTypInvalid, hookMustNotRun: true},
		{name: "typ missing", token: tokenWith(func(h map[string]any) { delete(h, "typ") }, nil), want: ErrStatusListTokenTypInvalid, hookMustNotRun: true},
		{name: "typ with media type prefix", token: tokenWith(func(h map[string]any) { h["typ"] = "application/statuslist+jwt" }, nil), want: ErrStatusListTokenTypInvalid, hookMustNotRun: true},
		{name: "typ not a string", token: tokenWith(func(h map[string]any) { h["typ"] = 1 }, nil), want: ErrStatusListTokenTypInvalid, hookMustNotRun: true},
		{
			name: "alg none",
			token: func(t *testing.T, h *harness) string {
				header := map[string]any{"alg": "none", "typ": "statuslist+jwt"}
				return encodeSegment(t, header) + "." + encodeSegment(t, defaultClaims(h.uri)) + "."
			},
			want:           ErrStatusListAlgorithmUnsupported,
			hookMustNotRun: true,
		},
		{
			name: "alg HS256",
			token: func(t *testing.T, h *harness) string {
				header := map[string]any{"alg": "HS256", "typ": "statuslist+jwt", "kid": "key-1"}
				return signHS256(t, []byte(strings.Repeat("s", 32)), header, defaultClaims(h.uri))
			},
			want:           ErrStatusListAlgorithmUnsupported,
			hookMustNotRun: true,
		},
		{name: "alg missing", token: tokenWith(func(h map[string]any) { delete(h, "alg") }, nil), want: ErrStatusListAlgorithmUnsupported, hookMustNotRun: true},
		{
			name:           "alg outside a narrowed checker set",
			configure:      func(_ *harness, c *Checker) { c.SigningAlgorithms = []jose.SignatureAlgorithm{jose.EdDSA} },
			want:           ErrStatusListAlgorithmUnsupported,
			hookMustNotRun: true,
		},
		{name: "two segments", token: func(*testing.T, *harness) string { return "e30.e30" }, want: ErrStatusListTokenInvalid, hookMustNotRun: true},
		{name: "four segments", token: func(*testing.T, *harness) string { return "e30.e30.e30.e30" }, want: ErrStatusListTokenInvalid, hookMustNotRun: true},
		{name: "header not base64url", token: func(*testing.T, *harness) string { return "!!.e30.sig" }, want: ErrStatusListTokenInvalid, hookMustNotRun: true},
		{
			name: "header not an object",
			token: func(t *testing.T, h *harness) string {
				return signES256(t, h.key, `["statuslist+jwt"]`, defaultClaims(h.uri))
			},
			want:           ErrStatusListTokenInvalid,
			hookMustNotRun: true,
		},
		{
			name: "header null",
			token: func(t *testing.T, h *harness) string {
				return signES256(t, h.key, `null`, defaultClaims(h.uri))
			},
			want:           ErrStatusListTokenInvalid,
			hookMustNotRun: true,
		},
		{name: "critical extension", token: tokenWith(func(h map[string]any) { h["crit"] = []string{"exp"}; h["exp"] = 1 }, nil), want: ErrStatusListTokenInvalid, hookMustNotRun: true},
		{name: "unencoded payload option", token: tokenWith(func(h map[string]any) { h["b64"] = false; h["crit"] = []string{"b64"} }, nil), want: ErrStatusListTokenInvalid, hookMustNotRun: true},
		{
			name: "duplicate kid members",
			token: func(t *testing.T, h *harness) string {
				return signES256(t, h.key, `{"alg":"ES256","typ":"statuslist+jwt","kid":"key-1","kid":"key-2"}`, defaultClaims(h.uri))
			},
			want:           ErrStatusListTokenInvalid,
			hookMustNotRun: true,
		},
		{
			name: "payload not an object",
			token: func(t *testing.T, h *harness) string {
				return signES256(t, h.key, defaultHeader(), `"status"`)
			},
			want:           ErrStatusListTokenInvalid,
			hookMustNotRun: true,
		},
		{
			name: "payload with trailing data",
			token: func(t *testing.T, h *harness) string {
				claims, _ := json.Marshal(defaultClaims(h.uri))
				return signES256(t, h.key, defaultHeader(), string(claims)+"{}")
			},
			want:           ErrStatusListTokenInvalid,
			hookMustNotRun: true,
		},
		{name: "iss missing", token: claimsWith(func(c map[string]any) { delete(c, "iss") }), want: ErrStatusListTokenInvalid, hookMustNotRun: true},
		{name: "iss empty", token: claimsWith(func(c map[string]any) { c["iss"] = "" }), want: ErrStatusListTokenInvalid, hookMustNotRun: true},
		{name: "iss not a string", token: claimsWith(func(c map[string]any) { c["iss"] = 7 }), want: ErrStatusListTokenInvalid, hookMustNotRun: true},
	})
}

func TestCheckReferenceRefusesUnresolvedKeys(t *testing.T) {
	hookFailure := errors.New("jwks endpoint unreachable")
	resolveWith := func(keys []jose.JSONWebKey, err error) func(*harness, *Checker) {
		return func(_ *harness, c *Checker) {
			c.ResolveIssuerKeys = func(context.Context, string, map[string]any) ([]jose.JSONWebKey, error) {
				return keys, err
			}
		}
	}
	runFailureCases(t, []failureCase{
		{name: "no hook", configure: func(_ *harness, c *Checker) { c.ResolveIssuerKeys = nil }, want: ErrStatusListIssuerKeyUnresolved},
		{name: "hook error", configure: resolveWith(nil, hookFailure), want: ErrStatusListIssuerKeyUnresolved},
		{name: "no keys", configure: resolveWith(nil, nil), want: ErrStatusListIssuerKeyUnresolved},
		{name: "empty key set", configure: resolveWith([]jose.JSONWebKey{}, nil), want: ErrStatusListIssuerKeyUnresolved},
		{
			name: "private key",
			configure: func(h *harness, c *Checker) {
				resolveWith([]jose.JSONWebKey{{Key: h.key, KeyID: "key-1"}}, nil)(h, c)
			},
			want: ErrStatusListIssuerKeyUnresolved,
		},
		{
			name: "private key alongside a public one",
			configure: func(h *harness, c *Checker) {
				resolveWith([]jose.JSONWebKey{publicJWK(h.key, "key-1"), {Key: h.key, KeyID: "key-2"}}, nil)(h, c)
			},
			want: ErrStatusListIssuerKeyUnresolved,
		},
		{name: "symmetric key", configure: resolveWith([]jose.JSONWebKey{{Key: []byte(strings.Repeat("s", 32))}}, nil), want: ErrStatusListIssuerKeyUnresolved},
		{name: "empty key", configure: resolveWith([]jose.JSONWebKey{{}}, nil), want: ErrStatusListIssuerKeyUnresolved},
	})

	t.Run("hook error stays in the chain", func(t *testing.T) {
		h := newHarness(t)
		h.serveToken(signES256(t, h.key, defaultHeader(), defaultClaims(h.uri)))
		checker := h.checker()
		resolveWith(nil, hookFailure)(h, checker)
		_, err := checker.CheckReference(context.Background(), testIssuer, h.reference(0))
		if !errors.Is(err, hookFailure) {
			t.Fatalf("err = %v, want it to wrap the hook error", err)
		}
	})
}

func TestCheckReferenceRefusesUnverifiedSignatures(t *testing.T) {
	runFailureCases(t, []failureCase{
		{
			name: "signed by another key",
			token: func(t *testing.T, h *harness) string {
				return signES256(t, testutil.NewP256Key(t), defaultHeader(), defaultClaims(h.uri))
			},
			want: ErrStatusListSignatureInvalid,
		},
		{
			name: "payload altered after signing",
			token: func(t *testing.T, h *harness) string {
				token := signES256(t, h.key, defaultHeader(), defaultClaims(h.uri))
				parts := strings.Split(token, ".")
				altered := defaultClaims(h.uri)
				altered["status_list"] = map[string]any{"bits": 1, "lst": zlibList(t, []byte{0, 0})}
				parts[1] = encodeSegment(t, altered)
				return strings.Join(parts, ".")
			},
			want: ErrStatusListSignatureInvalid,
		},
		{
			name: "only key is restricted to another alg",
			configure: func(h *harness, c *Checker) {
				key := publicJWK(h.key, "key-1")
				key.Algorithm = string(jose.ES384)
				c.ResolveIssuerKeys = func(context.Context, string, map[string]any) ([]jose.JSONWebKey, error) {
					return []jose.JSONWebKey{key}, nil
				}
			},
			want: ErrStatusListSignatureInvalid,
		},
		{
			name: "only key is an encryption key",
			configure: func(h *harness, c *Checker) {
				key := publicJWK(h.key, "key-1")
				key.Use = "enc"
				c.ResolveIssuerKeys = func(context.Context, string, map[string]any) ([]jose.JSONWebKey, error) {
					return []jose.JSONWebKey{key}, nil
				}
			},
			want: ErrStatusListSignatureInvalid,
		},
		{
			name:  "header alg does not match the key curve",
			token: tokenWith(func(h map[string]any) { h["alg"] = "ES384" }, nil),
			configure: func(h *harness, c *Checker) {
				key := publicJWK(h.key, "key-1")
				key.Algorithm = ""
				c.ResolveIssuerKeys = func(context.Context, string, map[string]any) ([]jose.JSONWebKey, error) {
					return []jose.JSONWebKey{key}, nil
				}
			},
			want: ErrStatusListSignatureInvalid,
		},
	})
}

func TestCheckReferenceRefusesInvalidVerifiedClaims(t *testing.T) {
	runFailureCases(t, []failureCase{
		{name: "sub for another list", token: claimsWith(func(c map[string]any) { c["sub"] = "https://issuer.example.test/status/other" }), want: ErrStatusListTokenInvalid},
		{name: "sub missing", token: claimsWith(func(c map[string]any) { delete(c, "sub") }), want: ErrStatusListTokenInvalid},
		{name: "sub with trailing slash", token: tokenWith(nil, nil), uri: func(h *harness) string { return h.uri + "/" }, want: ErrStatusListTokenInvalid},
		{name: "iat missing", token: claimsWith(func(c map[string]any) { delete(c, "iat") }), want: ErrStatusListTokenInvalid},
		{name: "iat null", token: claimsWith(func(c map[string]any) { c["iat"] = nil }), want: ErrStatusListTokenInvalid},
		{name: "iat string", token: claimsWith(func(c map[string]any) { c["iat"] = "1768000000" }), want: ErrStatusListTokenInvalid},
		{name: "iat out of range", token: claimsWith(func(c map[string]any) { c["iat"] = 1e300 }), want: ErrStatusListTokenInvalid},
		{name: "exp string", token: claimsWith(func(c map[string]any) { c["exp"] = "never" }), want: ErrStatusListTokenInvalid},
		{name: "nbf in the future", token: claimsWith(func(c map[string]any) { c["nbf"] = testNow.Unix() + 3600 }), want: ErrStatusListTokenInvalid},
		{name: "nbf string", token: claimsWith(func(c map[string]any) { c["nbf"] = "soon" }), want: ErrStatusListTokenInvalid},
		{name: "ttl zero", token: claimsWith(func(c map[string]any) { c["ttl"] = 0 }), want: ErrStatusListTokenInvalid},
		{name: "ttl negative", token: claimsWith(func(c map[string]any) { c["ttl"] = -1 }), want: ErrStatusListTokenInvalid},
		{name: "ttl string", token: claimsWith(func(c map[string]any) { c["ttl"] = "60" }), want: ErrStatusListTokenInvalid},
		{name: "ttl null", token: claimsWith(func(c map[string]any) { c["ttl"] = nil }), want: ErrStatusListTokenInvalid},
		{name: "status_list missing", token: claimsWith(func(c map[string]any) { delete(c, "status_list") }), want: ErrStatusListTokenInvalid},
		{name: "status_list array", token: claimsWith(func(c map[string]any) { c["status_list"] = []any{1} }), want: ErrStatusListTokenInvalid},
		{name: "bits 3", token: claimsWith(func(c map[string]any) { c["status_list"] = map[string]any{"bits": 3, "lst": ietfOneBitList} }), want: ErrStatusListTokenInvalid},
		{name: "bits 1.5", token: claimsWith(func(c map[string]any) { c["status_list"] = map[string]any{"bits": 1.5, "lst": ietfOneBitList} }), want: ErrStatusListTokenInvalid},
		{name: "bits string", token: claimsWith(func(c map[string]any) { c["status_list"] = map[string]any{"bits": "1", "lst": ietfOneBitList} }), want: ErrStatusListTokenInvalid},
		{name: "lst missing", token: claimsWith(func(c map[string]any) { c["status_list"] = map[string]any{"bits": 1} }), want: ErrStatusListTokenInvalid},
		{name: "lst empty", token: claimsWith(func(c map[string]any) { c["status_list"] = map[string]any{"bits": 1, "lst": ""} }), want: ErrStatusListTokenInvalid},
	})
}

func TestCheckReferenceRefusesExpiredTokens(t *testing.T) {
	skew := func(d time.Duration) func(*harness, *Checker) {
		return func(_ *harness, c *Checker) { c.ClockSkew = d }
	}
	runFailureCases(t, []failureCase{
		{name: "exp passed", token: claimsWith(func(c map[string]any) { c["exp"] = testNow.Unix() - 1 }), want: ErrStatusListTokenExpired},
		{name: "exp equals now", token: claimsWith(func(c map[string]any) { c["exp"] = testNow.Unix() }), want: ErrStatusListTokenExpired},
		{name: "exp passed beyond skew", token: claimsWith(func(c map[string]any) { c["exp"] = testNow.Unix() - 120 }), configure: skew(time.Minute), want: ErrStatusListTokenExpired},
	})
}

func TestCheckReferenceRefusesUndecodableLists(t *testing.T) {
	list := func(bits int, lst string) func(*testing.T, *harness) string {
		return func(t *testing.T, h *harness) string {
			claims := defaultClaims(h.uri)
			claims["status_list"] = map[string]any{"bits": bits, "lst": lst}
			return signES256(t, h.key, defaultHeader(), claims)
		}
	}
	runFailureCases(t, []failureCase{
		{name: "not base64url", token: list(1, "not-a-status-list!"), want: ErrStatusListDecodeFailed},
		{name: "not zlib", token: list(1, base64.RawURLEncoding.EncodeToString([]byte("plain"))), want: ErrStatusListDecodeFailed},
		{
			name: "compression bomb",
			token: func(t *testing.T, h *harness) string {
				return list(1, zlibList(t, make([]byte, 2<<20)))(t, h)
			},
			want: ErrStatusListDecodeFailed,
		},
		{
			name:      "list over a configured cap",
			token:     list(8, zlibList(t, make([]byte, 64))),
			configure: func(_ *harness, c *Checker) { c.MaxDecompressedBytes = 32 },
			want:      ErrStatusListDecodeFailed,
		},
		{name: "index past the list", token: list(1, ietfOneBitList), index: 16, want: ErrStatusListIndexOutOfRange},
		{name: "index past a two-bit list", token: list(2, zlibList(t, []byte{0xC9})), index: 4, want: ErrStatusListIndexOutOfRange},
	})
}

// --- ParseReference, transport and HTTP client handling -------------------

func TestParseReference(t *testing.T) {
	const uri = "https://issuer.example.test/status/1"
	valid := []struct {
		name string
		idx  any
		want int64
	}{
		{"json.Number", json.Number("3"), 3},
		{"float64", float64(3), 3},
		{"int", 3, 3},
		{"int64", int64(3), 3},
		{"zero", float64(0), 0},
		{"max exact", json.Number("9007199254740991"), maxExactInteger},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			if test.want > math.MaxInt {
				t.Skip("int cannot hold this index on this platform")
			}
			reference, err := ParseReference(map[string]any{
				"status_list": map[string]any{"idx": test.idx, "uri": uri},
				"other":       map[string]any{"ignored": true},
			})
			if err != nil {
				t.Fatal(err)
			}
			if int64(reference.Index) != test.want || reference.URI != uri {
				t.Fatalf("reference = %+v", reference)
			}
		})
	}

	invalid := []struct {
		name   string
		status map[string]any
	}{
		{"nil status", nil},
		{"no status_list", map[string]any{"status_assertion": map[string]any{}}},
		{"status_list null", map[string]any{"status_list": nil}},
		{"status_list array", map[string]any{"status_list": []any{}}},
		{"status_list string", map[string]any{"status_list": uri}},
		{"idx missing", map[string]any{"status_list": map[string]any{"uri": uri}}},
		{"idx string", map[string]any{"status_list": map[string]any{"idx": "1", "uri": uri}}},
		{"idx negative", map[string]any{"status_list": map[string]any{"idx": float64(-1), "uri": uri}}},
		{"idx fraction", map[string]any{"status_list": map[string]any{"idx": 1.5, "uri": uri}}},
		{"idx past 2^53-1", map[string]any{"status_list": map[string]any{"idx": json.Number("9007199254740992"), "uri": uri}}},
		{"uri missing", map[string]any{"status_list": map[string]any{"idx": float64(1)}}},
		{"uri empty", map[string]any{"status_list": map[string]any{"idx": float64(1), "uri": ""}}},
		{"uri not a string", map[string]any{"status_list": map[string]any{"idx": float64(1), "uri": 5}}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			reference, err := ParseReference(test.status)
			if reference != nil {
				t.Fatalf("reference = %+v, want nil", reference)
			}
			assertSentinel(t, err, ErrStatusReferenceInvalid)
		})
	}
}

func TestCheckRefusesAnUnparsableStatusClaimWithoutFetching(t *testing.T) {
	h := newHarness(t)
	h.serveToken("unused")
	_, err := h.checker().Check(context.Background(), testIssuer, map[string]any{"status_list": map[string]any{"idx": "0", "uri": h.uri}})
	assertSentinel(t, err, ErrStatusReferenceInvalid)
	if h.requests.Load() != 0 {
		t.Fatal("endpoint was requested")
	}
}

func TestCheckReferenceAllowsCleartextOnlyWhenEnabled(t *testing.T) {
	key := testutil.NewP256Key(t)
	server := httptest.NewServer(nil)
	t.Cleanup(server.Close)
	uri := server.URL + statusPath
	token := signES256(t, key, defaultHeader(), defaultClaims(uri))
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", statusListTokenMediaType)
		_, _ = w.Write([]byte(token))
	})
	checker := &Checker{
		Now: func() time.Time { return testNow },
		ResolveIssuerKeys: func(context.Context, string, map[string]any) ([]jose.JSONWebKey, error) {
			return []jose.JSONWebKey{publicJWK(key, "key-1")}, nil
		},
	}
	_, err := checker.CheckReference(context.Background(), testIssuer, Reference{URI: uri, Index: 0})
	assertSentinel(t, err, ErrStatusReferenceInvalid)

	checker.AllowHTTP = true
	status, err := checker.CheckReference(context.Background(), testIssuer, Reference{URI: uri, Index: 0})
	if err != nil {
		t.Fatal(err)
	}
	if status.Value != 1 {
		t.Fatalf("value = %d", status.Value)
	}
}

func TestCheckReferenceDoesNotMutateTheCallerClient(t *testing.T) {
	h := newHarness(t)
	h.serveToken(signES256(t, h.key, defaultHeader(), defaultClaims(h.uri)))
	checker := h.checker()
	if checker.HTTPClient.CheckRedirect != nil {
		t.Fatal("precondition: test client has a redirect policy")
	}
	if _, err := checker.CheckReference(context.Background(), testIssuer, h.reference(0)); err != nil {
		t.Fatal(err)
	}
	if checker.HTTPClient.CheckRedirect != nil {
		t.Fatal("caller-owned client was given a redirect policy")
	}
}

func TestCheckReferenceHonoursContextCancellation(t *testing.T) {
	h := newHarness(t)
	h.serveToken(signES256(t, h.key, defaultHeader(), defaultClaims(h.uri)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := h.checker().CheckReference(ctx, testIssuer, h.reference(0))
	assertSentinel(t, err, ErrStatusListFetchFailed)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want it to wrap context.Canceled", err)
	}
}

func TestCheckReferenceAcceptsEveryAcceptedAlgorithmByDefault(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []jose.SignatureAlgorithm{jose.RS384, jose.RS512} {
		t.Run(string(algorithm), func(t *testing.T) {
			h := newHarness(t)
			signer, err := jose.NewSigner(
				jose.SigningKey{Algorithm: algorithm, Key: jose.JSONWebKey{Key: private, KeyID: "rsa-key"}},
				(&jose.SignerOptions{}).WithType("statuslist+jwt"),
			)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(defaultClaims(h.uri))
			if err != nil {
				t.Fatal(err)
			}
			signed, err := signer.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			token, err := signed.CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			h.serveToken(token)
			if _, err := h.checker(jose.JSONWebKey{Key: &private.PublicKey, KeyID: "rsa-key"}).CheckReference(context.Background(), testIssuer, h.reference(1)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
