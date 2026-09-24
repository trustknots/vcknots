package x509

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// Bound ASN.1 work before crypto/x509 allocates the parsed entries. Extension
// OCTET STRING contents are validated separately for the fields we understand.
func validateCRLDERBudget(der []byte) error {
	budget := min(1_000_000, len(der)/4+1024)
	var visit func([]byte, int) error
	visit = func(content []byte, depth int) error {
		if depth > 32 {
			return fmt.Errorf("CRL DER nesting exceeds limit")
		}
		for len(content) > 0 {
			budget--
			if budget < 0 {
				return fmt.Errorf("CRL DER node count exceeds limit")
			}
			var value asn1.RawValue
			rest, err := asn1.Unmarshal(content, &value)
			if err != nil {
				return err
			}
			if value.IsCompound {
				if err := visit(value.Bytes, depth+1); err != nil {
					return err
				}
			}
			content = rest
		}
		return nil
	}
	return visit(der, 0)
}

func parseStrictCRL(der []byte) (*x509.RevocationList, error) {
	if len(der) == 0 || len(der) > MaxCRLBytes {
		return nil, fmt.Errorf("CRL DER is empty or exceeds 8 MiB")
	}
	if err := validateCRLDERBudget(der); err != nil {
		return nil, err
	}
	outer, err := crlDERSequence(der)
	if err != nil || len(outer) != 3 {
		return nil, fmt.Errorf("malformed CRL envelope")
	}
	tbs, err := crlDERSequence(outer[0].FullBytes)
	if err != nil || len(tbs) < 4 {
		return nil, fmt.Errorf("malformed CRL TBS sequence")
	}
	// crypto/x509 currently supports v2 CRLs. Verify all remaining fields
	// explicitly, because its parser can leave signed trailing data unread.
	index := 4 // version, signature algorithm, issuer, thisUpdate
	if index < len(tbs) && tbs[index].Class == asn1.ClassUniversal &&
		(tbs[index].Tag == asn1.TagUTCTime || tbs[index].Tag == asn1.TagGeneralizedTime) {
		index++
	}
	if index < len(tbs) && tbs[index].Class == asn1.ClassUniversal && tbs[index].Tag == asn1.TagSequence {
		entries, err := crlDERChildren(tbs[index].Bytes)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			fields, err := crlDERSequence(entry.FullBytes)
			if err != nil || len(fields) < 2 || len(fields) > 3 {
				return nil, fmt.Errorf("malformed CRL entry")
			}
			var serial *big.Int
			if _, err := asn1.Unmarshal(fields[0].FullBytes, &serial); err != nil || serial.Sign() < 0 {
				return nil, fmt.Errorf("malformed CRL entry serial")
			}
			if len(fields) == 3 {
				if _, err := parseCRLExtensions(fields[2].FullBytes); err != nil {
					return nil, err
				}
			}
		}
		index++
	}
	if index < len(tbs) && tbs[index].Class == asn1.ClassContextSpecific && tbs[index].Tag == 0 && tbs[index].IsCompound {
		if _, err := parseCRLExtensions(tbs[index].Bytes); err != nil {
			return nil, err
		}
		index++
	}
	if index != len(tbs) {
		return nil, fmt.Errorf("unhandled trailing CRL TBS fields")
	}
	return x509.ParseRevocationList(der)
}
