package x509

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
)

// CRLCheckErrorKind distinguishes an unavailable status from a revoked certificate.
type CRLCheckErrorKind string

// CRL check error kinds.
const (
	// CRLErrorUnsupported reports an invalid input path, a certificate without a
	// usable CRL distribution point, or a CRL feature this package does not handle.
	CRLErrorUnsupported CRLCheckErrorKind = "unsupported"
	// CRLErrorBudget reports that the checker's CRL fetch budget was exhausted.
	CRLErrorBudget CRLCheckErrorKind = "budget"
	// CRLErrorFetch reports a failed or cancelled CRL download.
	CRLErrorFetch CRLCheckErrorKind = "fetch"
	// CRLErrorParse reports a CRL that could not be parsed.
	CRLErrorParse CRLCheckErrorKind = "parse"
	// CRLErrorIssuer reports a CRL issuer that does not match the certificate
	// issuer, or an issuer not permitted to sign CRLs.
	CRLErrorIssuer CRLCheckErrorKind = "issuer"
	// CRLErrorSignature reports a CRL whose signature does not verify.
	CRLErrorSignature CRLCheckErrorKind = "signature"
	// CRLErrorStale reports a CRL without nextUpdate or not current at the
	// verification time.
	CRLErrorStale CRLCheckErrorKind = "stale"
	// CRLErrorScope reports a CRL whose scope does not cover the certificate.
	CRLErrorScope CRLCheckErrorKind = "scope"
	// CRLErrorRevoked reports a certificate listed as revoked.
	CRLErrorRevoked CRLCheckErrorKind = "revoked"
)

// CRLCheckError retains the cause for errors.Is/errors.As and observability.
type CRLCheckError struct {
	Kind         CRLCheckErrorKind
	URL          string
	Subject      string
	SerialNumber string
	Reason       string
	Err          error
}

// Error implements error.
func (e *CRLCheckError) Error() string {
	return fmt.Sprintf("certificate revocation %s: %s", e.Kind, e.Reason)
}

// Unwrap returns the wrapped error.
func (e *CRLCheckError) Unwrap() error { return e.Err }

// ErrorCode names the revocation verdict this check reached. Only a revoked
// certificate and an exhausted fetch budget are conditions of their own: every
// other kind — no usable distribution point, a download, parse, issuer,
// signature, staleness or scope failure — means the status could not be
// established, which is a different answer from "revoked" and is reported as
// such.
func (e *CRLCheckError) ErrorCode() string {
	switch e.Kind {
	case CRLErrorRevoked:
		return "x509_chain_revoked"
	case CRLErrorBudget:
		return "crl_budget_exhausted"
	default:
		return "x509_chain_revocation_unknown"
	}
}

// CRLCheckResult counts the certificates below the anchor by how their status
// was established.
type CRLCheckResult struct {
	// CheckedCertificates had their serial looked up in a current CRL.
	CheckedCertificates int
	// NoMechanismCertificates publish no CRL distribution point, so no status
	// was established for them: they advertise no revocation mechanism at
	// all, or only OCSP, which this package does not consult.
	NoMechanismCertificates int
}

// CRLCheckerOptions supplies the guarded outbound client and optional durable
// DER cache. A checker belongs to one verification session, never a global pool.
type CRLCheckerOptions struct {
	HTTPClient   *http.Client
	Cache        CRLCache
	MaxFetches   int
	FetchTimeout time.Duration
	// RequireStatus refuses a certificate that publishes no CRL distribution
	// point, including one that advertises only OCSP. Without it such a
	// certificate is counted in CRLCheckResult.NoMechanismCertificates.
	RequireStatus bool
	// ClockSkew is how far a CRL's thisUpdate may lie ahead of the
	// verification time. Zero means defaultCRLClockSkew (five minutes).
	ClockSkew time.Duration
}

const defaultCRLClockSkew = 5 * time.Minute

// CRLChecker shares downloads (including failures) between candidate paths.
// PKIX validation must succeed before a caller supplies a path to Check.
type CRLChecker struct {
	client        *http.Client
	cache         CRLCache
	maxFetches    int
	fetchTimeout  time.Duration
	requireStatus bool
	clockSkew     time.Duration
	mu            sync.Mutex
	fetches       int
	loads         map[string]*crlDownload
}

// NewCRLChecker returns a CRLChecker for options. HTTPClient is required and is
// used without following redirects; zero MaxFetches, FetchTimeout and ClockSkew
// default to 16 fetches, 10 seconds and five minutes.
func NewCRLChecker(options CRLCheckerOptions) (*CRLChecker, error) {
	if options.HTTPClient == nil {
		return nil, fmt.Errorf("CRL HTTP client is required")
	}
	if options.MaxFetches < 0 || options.FetchTimeout < 0 || options.ClockSkew < 0 {
		return nil, fmt.Errorf("CRL fetch budget, timeout and clock skew must not be negative")
	}
	if options.ClockSkew == 0 {
		options.ClockSkew = defaultCRLClockSkew
	}
	if options.MaxFetches == 0 {
		options.MaxFetches = 16
	}
	if options.FetchTimeout == 0 {
		options.FetchTimeout = 10 * time.Second
	}
	return &CRLChecker{
		client: httpfetch.NoRedirect(options.HTTPClient), cache: options.Cache, maxFetches: options.MaxFetches,
		fetchTimeout: options.FetchTimeout, requireStatus: options.RequireStatus, clockSkew: options.ClockSkew,
		loads: make(map[string]*crlDownload),
	}, nil
}

// Check verifies revocation below the anchor in a leaf-first, anchor-last path.
// It never consults OCSP and never treats a missing CRL distribution point as
// a CRL verdict. A distribution point extension that names no usable http(s)
// CRL is always refused.
func (c *CRLChecker) Check(ctx context.Context, path []*x509.Certificate, now time.Time) (CRLCheckResult, error) {
	result := CRLCheckResult{}
	if len(path) == 0 || now.IsZero() {
		return result, &CRLCheckError{Kind: CRLErrorUnsupported, Reason: "nonempty path and verification time are required"}
	}
	for _, cert := range path {
		if cert == nil || cert.SerialNumber == nil {
			return result, &CRLCheckError{Kind: CRLErrorUnsupported, Reason: "path contains an invalid certificate"}
		}
	}
	for i, cert := range path[:len(path)-1] {
		if err := ctx.Err(); err != nil {
			return result, crlError(CRLErrorFetch, cert, "", "verification context ended", err)
		}
		urls, advertised, err := certificateCRLURLs(cert)
		if err != nil {
			return result, crlError(CRLErrorUnsupported, cert, "", err.Error(), err)
		}
		if len(urls) == 0 {
			if advertised || c.requireStatus {
				return result, crlError(CRLErrorUnsupported, cert, "", "no usable CRL distribution point; OCSP is not consulted", nil)
			}
			result.NoMechanismCertificates++
			continue
		}
		issuer := path[i+1]
		// RFC 5280 Section 6.3.3(f): cRLSign is required when the issuer
		// carries a key usage extension, as keyCertSign is on the path.
		if hasKeyUsage(issuer) && issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
			return result, crlError(CRLErrorIssuer, cert, "", "issuer has no cRLSign key usage", nil)
		}
		var lastErr *CRLCheckError
		for _, location := range urls {
			lastErr = c.checkCRL(ctx, cert, issuer, location, urls, now)
			if lastErr == nil {
				break
			}
			if lastErr.Kind == CRLErrorRevoked || lastErr.Kind == CRLErrorBudget {
				return result, lastErr
			}
		}
		if lastErr != nil {
			return result, lastErr
		}
		result.CheckedCertificates++
	}
	return result, nil
}

func crlError(kind CRLCheckErrorKind, cert *x509.Certificate, location, reason string, err error) *CRLCheckError {
	return &CRLCheckError{Kind: kind, URL: location, Subject: cert.Subject.String(),
		SerialNumber: cert.SerialNumber.Text(16), Reason: reason, Err: err}
}

// checkCRL checks cert against the CRL at location, one of the certificate's
// distribution point URLs listed in distributionPoints.
func (c *CRLChecker) checkCRL(ctx context.Context, cert, issuer *x509.Certificate, location string, distributionPoints []string, now time.Time) *CRLCheckError {
	loaded, loadErr := c.load(ctx, location, now)
	if loadErr != nil {
		return crlError(loadErr.Kind, cert, location, loadErr.Reason, loadErr.Err)
	}
	crl, err := parseStrictCRL(loaded.der)
	if err != nil {
		return crlError(CRLErrorParse, cert, location, "CRL could not be parsed", err)
	}
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) ||
		(len(crl.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 && !bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId)) {
		return crlError(CRLErrorIssuer, cert, location, "CRL issuer does not match the certificate issuer", nil)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return crlError(CRLErrorSignature, cert, location, "CRL issuer signature does not verify", err)
	}
	if crl.NextUpdate.IsZero() || now.Add(c.clockSkew).Before(crl.ThisUpdate) || now.After(crl.NextUpdate) {
		return crlError(CRLErrorStale, cert, location, "CRL has no nextUpdate or is not current", nil)
	}
	if err := checkCRLExtensions(crl); err != nil {
		return crlError(CRLErrorUnsupported, cert, location, err.Error(), err)
	}
	// A cache stores issuer-signed, current, understood DER, including a CRL
	// that may be out of scope for this particular certificate. Every use
	// verifies it again; neither scope nor non-revocation is cached.
	c.remember(ctx, location, loaded, crl)
	if err := checkCRLScope(crl, cert, distributionPoints); err != nil {
		return crlError(CRLErrorScope, cert, location, err.Error(), err)
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return crlError(CRLErrorRevoked, cert, location, "certificate serial is listed as revoked", nil)
		}
	}
	return nil
}
