package x509

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

func CheckIfCertsRevoked(certChain []*x509.Certificate) error {
	var lastErr error = nil

	for i := 0; i < len(certChain); i++ {
		cert := certChain[i]
		issuer := certChain[i]
		if i < len(certChain)-1 {
			issuer = certChain[i+1]
		}

		// OCSP
		if len(cert.OCSPServer) > 0 {
			status, err := checkCertWithOCSP(cert, issuer)
			if err != nil {
				lastErr = err
				continue
			}
			if status == ocsp.Good {
				continue
			} else if status == ocsp.Revoked {
				lastErr = fmt.Errorf("ocsp response: revoked")
				continue
			}
		}

		if lastErr != nil {
			return lastErr
		}

		// CRL
		if len(cert.CRLDistributionPoints) > 0 {
			for _, distPoints := range cert.CRLDistributionPoints {
				err := checkCertWithCRL(cert, issuer, distPoints)
				if err != nil {
					lastErr = err
					break
				}
			}
		}
	}

	return lastErr
}

func checkCertWithCRL(cert *x509.Certificate, issuer *x509.Certificate, crlURL string) error {
	// Download CRL
	resp, err := http.Get(crlURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return err
	}

	// Verify CRL
	err = crl.CheckSignatureFrom(issuer)
	if err != nil {
		return err
	}

	// Revoke check
	if crl.NextUpdate.Before(time.Now()) {
		return errors.New("CRL is outdated")
	}
	for _, revokedCert := range crl.RevokedCertificateEntries {
		if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return errors.New("certificate was revoked")
		}
	}

	return nil
}

func checkCertWithOCSP(cert *x509.Certificate, issuer *x509.Certificate) (int, error) {
	if len(cert.OCSPServer) == 0 {
		return ocsp.Unknown, errors.New("no OCSP server specified")
	}

	var lastErr error
	for _, ocspURL := range cert.OCSPServer {
		opts := &ocsp.RequestOptions{Hash: crypto.SHA256}
		buffer, err := ocsp.CreateRequest(cert, issuer, opts)
		if err != nil {
			lastErr = err
			continue
		}
		httpRequest, err := http.NewRequest("POST", ocspURL, bytes.NewBuffer(buffer))
		if err != nil {
			lastErr = err
			continue
		}
		httpRequest.Header.Add("Content-Type", "application/ocsp-request")
		httpRequest.Header.Add("Accept", "application/ocsp-response")
		client := &http.Client{
			Timeout: 5 * time.Second,
		}
		httpResponse, err := client.Do(httpRequest)
		if err != nil {
			lastErr = err
			continue
		}
		defer httpResponse.Body.Close()
		if httpResponse.StatusCode != 200 {
			lastErr = fmt.Errorf("OCSP server returned status %d", httpResponse.StatusCode)
			continue
		}
		output, err := io.ReadAll(httpResponse.Body)
		if err != nil {
			lastErr = err
			continue
		}

		ocspResponse, err := ocsp.ParseResponseForCert(output, cert, issuer)
		if err != nil {
			lastErr = err
			continue
		}

		// Revoke check
		if time.Now().After(ocspResponse.NextUpdate) {
			lastErr = errors.New("stale OCSP response")
			continue
		}
		switch ocspResponse.Status {
		case ocsp.Good, ocsp.Revoked:
			return ocspResponse.Status, nil
		case ocsp.Unknown:
			lastErr = errors.New("certificate status unknown")
			continue
		}
	}

	return ocsp.Unknown, fmt.Errorf("all OCSP servers failed, last error: %v", lastErr)
}
