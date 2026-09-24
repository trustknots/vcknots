package x509

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
)

// MaxCRLBytes is the largest CRL, in bytes, that is downloaded or accepted
// from a CRLCache.
const MaxCRLBytes = 8 * 1024 * 1024

// MaxCRLCacheAge is how long a downloaded CRL may be served from a durable
// CRLCache before it is fetched again, independently of the CRL's own
// nextUpdate. An integrator that seeds or harvests the cache from its own
// storage derives the same expiry with NewCRLCacheEntry instead of copying this
// value, so a change here cannot silently invalidate a seeded cache.
const MaxCRLCacheAge = 24 * time.Hour

// CRLCache is a caller-owned durable DER cache, not a status/verdict cache.
// Load errors are treated as misses; Store errors do not weaken verification.
type CRLCache interface {
	Load(ctx context.Context, url string, now time.Time) (*CRLCacheEntry, error)
	Store(ctx context.Context, entry CRLCacheEntry) error
}

// CRLCacheEntry is one DER-encoded CRL held in a CRLCache, with its validity
// window, download time and cache expiry. Build entries with NewCRLCacheEntry.
type CRLCacheEntry struct {
	URL        string
	DER        []byte
	ThisUpdate time.Time
	NextUpdate time.Time
	FetchedAt  time.Time
	ExpiresAt  time.Time
}

type crlDownload struct {
	done      chan struct{}
	der       []byte
	fetchedAt time.Time
	network   bool
	err       *CRLCheckError
	remember  sync.Once
}

func (c *CRLChecker) load(ctx context.Context, location string, now time.Time) (*crlDownload, *CRLCheckError) {
	c.mu.Lock()
	loaded, exists := c.loads[location]
	if !exists {
		loaded = &crlDownload{done: make(chan struct{})}
		c.loads[location] = loaded
	}
	c.mu.Unlock()
	if exists {
		select {
		case <-loaded.done:
			return loaded, loaded.err
		case <-ctx.Done():
			return nil, &CRLCheckError{Kind: CRLErrorFetch, Reason: "CRL wait cancelled", Err: ctx.Err()}
		}
	}
	defer close(loaded.done)
	if c.cache != nil {
		cached, err := c.cache.Load(ctx, location, now)
		if err == nil && cached != nil && cacheEntryCurrent(cached, location, now) {
			if len(cached.DER) == 0 || len(cached.DER) > MaxCRLBytes {
				loaded.err = &CRLCheckError{Kind: CRLErrorParse, Reason: "cached CRL is empty or exceeds 8 MiB"}
				return loaded, loaded.err
			}
			loaded.der = append([]byte(nil), cached.DER...)
			loaded.fetchedAt = cached.FetchedAt
			return loaded, nil
		}
	}
	if err := ctx.Err(); err != nil {
		loaded.err = &CRLCheckError{Kind: CRLErrorFetch, Reason: "CRL request cancelled", Err: err}
		return loaded, loaded.err
	}
	c.mu.Lock()
	if c.fetches >= c.maxFetches {
		c.mu.Unlock()
		loaded.err = &CRLCheckError{Kind: CRLErrorBudget, Reason: fmt.Sprintf("CRL fetch budget of %d exhausted", c.maxFetches)}
		return loaded, loaded.err
	}
	c.fetches++
	c.mu.Unlock()
	der, err := c.fetch(ctx, location)
	if err != nil {
		loaded.err = &CRLCheckError{Kind: CRLErrorFetch, Reason: "CRL download failed", Err: err}
		return loaded, loaded.err
	}
	loaded.der, loaded.fetchedAt, loaded.network = der, now, true
	return loaded, nil
}

func cacheEntryCurrent(entry *CRLCacheEntry, location string, now time.Time) bool {
	if entry == nil {
		return false
	}
	return CRLCacheEntryCurrent(*entry, location, now)
}

// CRLCacheEntryCurrent reports whether a cached CRL may still be used for
// location at now. It is the exact freshness rule the checker applies to its
// own cache reads: the entry must belong to location, must have been fetched in
// the past, must be within MaxCRLCacheAge of its fetch time, and must be inside
// both its recorded expiry and the CRL's own nextUpdate. An integrator that
// keeps the DER in its own storage answers Load with the same rule instead of
// reimplementing it.
func CRLCacheEntryCurrent(entry CRLCacheEntry, location string, now time.Time) bool {
	return entry.URL == location && !entry.FetchedAt.IsZero() && !now.Before(entry.FetchedAt) &&
		!now.After(entry.FetchedAt.Add(MaxCRLCacheAge)) && !entry.ExpiresAt.IsZero() &&
		!now.After(entry.ExpiresAt) && !entry.NextUpdate.IsZero() && !now.After(entry.NextUpdate)
}

// NewCRLCacheEntry builds the cache entry the checker itself stores after a
// successful download: ExpiresAt is the earlier of fetchedAt plus
// MaxCRLCacheAge and the CRL's nextUpdate, and der is copied so the caller
// keeps no alias of the checker's buffer. An integrator that persists CRLs
// outside this process constructs its entries here, so a seeded entry is
// accepted by CRLCacheEntryCurrent under the same rule.
func NewCRLCacheEntry(location string, der []byte, thisUpdate, nextUpdate, fetchedAt time.Time) CRLCacheEntry {
	expiresAt := fetchedAt.Add(MaxCRLCacheAge)
	if !nextUpdate.IsZero() && nextUpdate.Before(expiresAt) {
		expiresAt = nextUpdate
	}
	return CRLCacheEntry{
		URL:        location,
		DER:        append([]byte(nil), der...),
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
		FetchedAt:  fetchedAt,
		ExpiresAt:  expiresAt,
	}
}

func (c *CRLChecker) remember(ctx context.Context, location string, loaded *crlDownload, crl *x509.RevocationList) {
	if c.cache == nil || !loaded.network {
		return
	}
	loaded.remember.Do(func() {
		_ = c.cache.Store(ctx, NewCRLCacheEntry(location, loaded.der, crl.ThisUpdate, crl.NextUpdate, loaded.fetchedAt))
	})
}

func canonicalCRLURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") ||
		u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.TrimSpace(raw) != raw {
		return "", fmt.Errorf("CRL distribution point requires an absolute http(s) URL without userinfo or fragment")
	}
	for _, value := range raw {
		if value < 0x21 || value > 0x7e {
			return "", fmt.Errorf("CRL URI is not IA5 text")
		}
	}
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		u.Host = strings.TrimSuffix(u.Host, ":"+u.Port())
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func (c *CRLChecker) fetch(ctx context.Context, location string) ([]byte, error) {
	if _, err := canonicalCRLURL(location); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/pkix-crl, application/octet-stream;q=0.9, */*;q=0.1")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("CRL returned HTTP %d; redirects are not followed", response.StatusCode)
	}
	der, err := httpfetch.ReadLimited(response, MaxCRLBytes)
	if err != nil {
		return nil, err
	}
	if len(der) == 0 {
		return nil, fmt.Errorf("CRL body is empty")
	}
	return der, nil
}
