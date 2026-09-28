package x509

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type crlTestCache struct {
	mu       sync.Mutex
	entries  map[string]CRLCacheEntry
	stores   int
	loadErr  error
	storeErr error
}

func (c *crlTestCache) Load(_ context.Context, location string, _ time.Time) (*CRLCacheEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loadErr != nil {
		return nil, c.loadErr
	}
	entry, ok := c.entries[location]
	if !ok {
		return nil, nil
	}
	entry.DER = append([]byte(nil), entry.DER...)
	return &entry, nil
}

func (c *crlTestCache) Store(_ context.Context, entry CRLCacheEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stores++
	if c.storeErr != nil {
		return c.storeErr
	}
	if c.entries == nil {
		c.entries = make(map[string]CRLCacheEntry)
	}
	entry.DER = append([]byte(nil), entry.DER...)
	c.entries[entry.URL] = entry
	return nil
}

func TestCRLSessionMemoSharesSuccessAndFailureBetweenCandidates(t *testing.T) {
	for _, success := range []bool{true, false} {
		ca := newCRLTestAuthority(t, nil)
		der := issueCRLTestDER(t, ca, nil)
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			time.Sleep(5 * time.Millisecond)
			if !success {
				w.WriteHeader(503)
				return
			}
			_, _ = w.Write(der)
		}))
		leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.CRLDistributionPoints = []string{server.URL} })
		checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client()})
		var workers sync.WaitGroup
		for range 10 {
			workers.Go(func() {
				_, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
				if success && err != nil {
					t.Error(err)
				}
				if !success {
					assertCRLTestKind(t, err, CRLErrorFetch)
				}
			})
		}
		workers.Wait()
		server.Close()
		if requests.Load() != 1 {
			t.Fatalf("memo fetched %d times", requests.Load())
		}
	}
}

func TestCRLFetchBudgetIsSharedAcrossCandidatePaths(t *testing.T) {
	for _, configured := range []int{0, 2, 20} {
		limit := configured
		if limit == 0 {
			limit = 16
		}
		ca := newCRLTestAuthority(t, nil)
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(503) }))
		checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client(), MaxFetches: configured})
		for i := range limit + 1 {
			leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) {
				cert.CRLDistributionPoints = []string{server.URL + "/" + strconv.Itoa(i)}
			})
			_, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
			if i == limit {
				assertCRLTestKind(t, err, CRLErrorBudget)
			} else {
				assertCRLTestKind(t, err, CRLErrorFetch)
			}
		}
		server.Close()
		if int(requests.Load()) != limit {
			t.Fatalf("budget %d downloaded %d times", limit, requests.Load())
		}
	}
}

func TestCRLHTTPRejectsRedirectsStatusEmptyOversizedAndCancellation(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { redirected.Add(1); _, _ = w.Write([]byte("target")) }))
	defer target.Close()
	tests := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
	}{
		{"redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }, 0},
		{"status", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }, 0},
		{"empty", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }, 0},
		{"declared size", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(MaxCRLBytes+1))
			w.WriteHeader(200)
		}, 0},
		{"stream size", func(w http.ResponseWriter, _ *http.Request) {
			w.(http.Flusher).Flush()
			_, _ = w.Write(make([]byte, MaxCRLBytes+1))
		}, 0},
		{"timeout", func(w http.ResponseWriter, r *http.Request) { w.(http.Flusher).Flush(); <-r.Context().Done() }, 20 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()
			checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client(), FetchTimeout: tt.timeout})
			if _, err := checker.fetch(context.Background(), server.URL); err == nil {
				t.Fatal("invalid HTTP response accepted")
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect target was contacted")
	}
	checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: target.Client()})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := checker.fetch(ctx, target.URL); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if redirected.Load() != 0 {
		t.Fatal("cancelled request reached server")
	}
}

func TestCRLDurableCacheSavesDownloadAndCapsRetention(t *testing.T) {
	for _, lifetime := range []time.Duration{time.Hour, 48 * time.Hour} {
		ca := newCRLTestAuthority(t, nil)
		der := issueCRLTestDER(t, ca, func(list *x509.RevocationList) { list.NextUpdate = ca.now.Add(lifetime) })
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); _, _ = w.Write(der) }))
		location := server.URL + "/crl"
		leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.CRLDistributionPoints = []string{location} })
		cache := &crlTestCache{}
		for range 2 {
			checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client(), Cache: cache})
			if _, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now); err != nil {
				t.Fatal(err)
			}
		}
		server.Close()
		if requests.Load() != 1 || cache.stores != 1 {
			t.Fatalf("cache did not save download: %d, %d", requests.Load(), cache.stores)
		}
		entry := cache.entries[location]
		if !entry.ExpiresAt.Equal(ca.now.Add(min(lifetime, 24*time.Hour))) || !entry.FetchedAt.Equal(ca.now) {
			t.Fatalf("incorrect retention: %+v", entry)
		}
	}
}

func TestCRLCacheMissesExpiredMetadataAndRevalidatesInvalidDER(t *testing.T) {
	ca := newCRLTestAuthority(t, nil)
	valid := issueCRLTestDER(t, ca, nil)
	stale := issueCRLTestDER(t, ca, func(list *x509.RevocationList) {
		list.ThisUpdate = ca.now.Add(-2 * time.Hour)
		list.NextUpdate = ca.now.Add(-time.Hour)
	})
	tests := []struct {
		name      string
		change    func(*CRLCacheEntry)
		kind      CRLCheckErrorKind
		downloads int32
	}{
		{"expired", func(entry *CRLCacheEntry) { entry.ExpiresAt = ca.now.Add(-time.Second) }, "", 1},
		{"older than ceiling", func(entry *CRLCacheEntry) { entry.FetchedAt = ca.now.Add(-25 * time.Hour) }, "", 1},
		{"future fetch time", func(entry *CRLCacheEntry) { entry.FetchedAt = ca.now.Add(time.Minute) }, "", 1},
		{"nextUpdate expired", func(entry *CRLCacheEntry) { entry.NextUpdate = ca.now.Add(-time.Minute) }, "", 1},
		{"foreign URL", func(entry *CRLCacheEntry) { entry.URL = "https://different.invalid/" }, "", 1},
		{"stale signed DER", func(entry *CRLCacheEntry) { entry.DER = stale }, CRLErrorStale, 0},
		{"malformed DER", func(entry *CRLCacheEntry) { entry.DER = []byte("invalid") }, CRLErrorParse, 0},
		{"oversized DER", func(entry *CRLCacheEntry) { entry.DER = make([]byte, MaxCRLBytes+1) }, CRLErrorParse, 0},
		{"empty DER", func(entry *CRLCacheEntry) { entry.DER = nil }, CRLErrorParse, 0},
		{"bad signature", func(entry *CRLCacheEntry) {
			entry.DER = append([]byte(nil), valid...)
			entry.DER[len(entry.DER)-1] ^= 1
		}, CRLErrorSignature, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); _, _ = w.Write(valid) }))
			defer server.Close()
			location := server.URL + "/crl"
			leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.CRLDistributionPoints = []string{location} })
			entry := CRLCacheEntry{URL: location, DER: valid, ThisUpdate: ca.now.Add(-time.Hour), NextUpdate: ca.now.Add(time.Hour), FetchedAt: ca.now.Add(-time.Minute), ExpiresAt: ca.now.Add(time.Hour)}
			tt.change(&entry)
			cache := &crlTestCache{entries: map[string]CRLCacheEntry{location: entry}}
			checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client(), Cache: cache})
			_, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
			if tt.kind != "" {
				assertCRLTestKind(t, err, tt.kind)
			} else if err != nil {
				t.Fatal(err)
			}
			if requests.Load() != tt.downloads {
				t.Fatalf("unexpected downloads: %d", requests.Load())
			}
		})
	}
}

func TestCRLCacheNeverReusesScopeOrRevocationVerdict(t *testing.T) {
	ca := newCRLTestAuthority(t, nil)
	var der []byte
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); _, _ = w.Write(der) }))
	defer server.Close()
	location := server.URL + "/crl"
	der = issueCRLTestDER(t, ca, func(list *x509.RevocationList) {
		list.ExtraExtensions = []pkix.Extension{crlTestIDP(t, location, crlTestFlag(1))}
		list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(999), RevocationTime: ca.now.Add(-time.Minute)}}
	})
	cache := &crlTestCache{}
	for _, scenario := range []struct {
		isCA   bool
		serial int64
		kind   CRLCheckErrorKind
	}{{true, 2, CRLErrorScope}, {false, 2, ""}, {false, 999, CRLErrorRevoked}} {
		leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) {
			cert.CRLDistributionPoints = []string{location}
			cert.IsCA = scenario.isCA
			cert.SerialNumber = big.NewInt(scenario.serial)
		})
		checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client(), Cache: cache})
		_, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
		if scenario.kind != "" {
			assertCRLTestKind(t, err, scenario.kind)
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 || cache.stores != 1 {
		t.Fatalf("scope-valid signed DER not shared: %d, %d", requests.Load(), cache.stores)
	}
}

func TestCRLCacheErrorsDoNotBypassVerification(t *testing.T) {
	ca := newCRLTestAuthority(t, nil)
	der := issueCRLTestDER(t, ca, nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(der) }))
	defer server.Close()
	leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.CRLDistributionPoints = []string{server.URL} })
	cache := &crlTestCache{loadErr: fmt.Errorf("cache unavailable"), storeErr: fmt.Errorf("cache unavailable")}
	checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client(), Cache: cache})
	if _, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now); err != nil {
		t.Fatal(err)
	}
	if cache.stores != 1 {
		t.Fatal("verified DER was not offered to cache")
	}
}

// TestExportedCRLCacheEntryHelpersMatchTheCheckersOwnRule pins the seeding
// contract an integrator depends on: an entry built by NewCRLCacheEntry is
// accepted by CRLCacheEntryCurrent under exactly the rule the checker applies
// to its own cache reads, so a durable cache seeded outside this process is
// never silently discarded.
func TestExportedCRLCacheEntryHelpersMatchTheCheckersOwnRule(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	location := "https://ca.example/crl"
	der := []byte{1, 2, 3}

	entry := NewCRLCacheEntry(location, der, now.Add(-time.Hour), now.Add(time.Hour), now)
	if !entry.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("ExpiresAt = %s, want the CRL nextUpdate", entry.ExpiresAt)
	}
	der[0] = 9
	if entry.DER[0] == 9 {
		t.Fatal("NewCRLCacheEntry kept an alias of the caller's DER")
	}
	if !CRLCacheEntryCurrent(entry, location, now) {
		t.Fatal("a freshly built entry is not current")
	}
	if !cacheEntryCurrent(&entry, location, now) {
		t.Fatal("the checker's own rule disagrees with CRLCacheEntryCurrent")
	}

	// A CRL that outlives the retention cap expires at MaxCRLCacheAge.
	long := NewCRLCacheEntry(location, der, now.Add(-time.Hour), now.Add(48*time.Hour), now)
	if !long.ExpiresAt.Equal(now.Add(MaxCRLCacheAge)) {
		t.Fatalf("ExpiresAt = %s, want fetchedAt plus MaxCRLCacheAge", long.ExpiresAt)
	}
	if CRLCacheEntryCurrent(long, location, now.Add(MaxCRLCacheAge+time.Second)) {
		t.Fatal("an entry past MaxCRLCacheAge is still current")
	}

	for name, check := range map[string]struct {
		entry CRLCacheEntry
		url   string
		now   time.Time
	}{
		"another URL":        {entry, "https://other.example/crl", now},
		"before the fetch":   {entry, location, now.Add(-time.Minute)},
		"past nextUpdate":    {entry, location, now.Add(2 * time.Hour)},
		"never fetched":      {CRLCacheEntry{URL: location, NextUpdate: now.Add(time.Hour), ExpiresAt: now.Add(time.Hour)}, location, now},
		"no recorded expiry": {CRLCacheEntry{URL: location, FetchedAt: now, NextUpdate: now.Add(time.Hour)}, location, now},
		"no CRL nextUpdate":  {CRLCacheEntry{URL: location, FetchedAt: now, ExpiresAt: now.Add(time.Hour)}, location, now},
		"zero value":         {CRLCacheEntry{}, location, now},
	} {
		if CRLCacheEntryCurrent(check.entry, check.url, check.now) {
			t.Fatalf("%s: entry was reported current", name)
		}
	}
	if cacheEntryCurrent(nil, location, now) {
		t.Fatal("a nil entry was reported current")
	}
}
