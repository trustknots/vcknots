package x509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"slices"
	"time"
)

// Object identifiers of RFC 5280 Sections 4.2 and 5.2-5.3.
var (
	crlDistributionPointsOID = asn1.ObjectIdentifier{2, 5, 29, 31}
	crlAuthorityInfoOID      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	crlOCSPMethodOID         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	crlIssuingPointOID       = asn1.ObjectIdentifier{2, 5, 29, 28}
	crlNumberOID             = asn1.ObjectIdentifier{2, 5, 29, 20}
	crlReasonCodeOID         = asn1.ObjectIdentifier{2, 5, 29, 21}
	crlInvalidityDateOID     = asn1.ObjectIdentifier{2, 5, 29, 24}
	crlDeltaIndicatorOID     = asn1.ObjectIdentifier{2, 5, 29, 27}
	crlCertificateIssuerOID  = asn1.ObjectIdentifier{2, 5, 29, 29}
	crlAuthorityKeyIDOID     = asn1.ObjectIdentifier{2, 5, 29, 35}
	crlFreshestOID           = asn1.ObjectIdentifier{2, 5, 29, 46}
)

// oidIn reports whether id is one of oids.
func oidIn(id asn1.ObjectIdentifier, oids ...asn1.ObjectIdentifier) bool {
	for _, oid := range oids {
		if id.Equal(oid) {
			return true
		}
	}
	return false
}

func crlDERValue(der []byte) (asn1.RawValue, error) {
	var value asn1.RawValue
	rest, err := asn1.Unmarshal(der, &value)
	if err != nil {
		return value, fmt.Errorf("invalid DER value: %w", err)
	}
	if len(rest) != 0 {
		return value, fmt.Errorf("trailing DER data")
	}
	return value, nil
}

func crlDERChildren(content []byte) ([]asn1.RawValue, error) {
	var children []asn1.RawValue
	for len(content) > 0 {
		var child asn1.RawValue
		rest, err := asn1.Unmarshal(content, &child)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
		content = rest
	}
	return children, nil
}

func crlDERSequence(der []byte) ([]asn1.RawValue, error) {
	value, err := crlDERValue(der)
	if err != nil || value.Class != asn1.ClassUniversal || value.Tag != asn1.TagSequence || !value.IsCompound {
		return nil, fmt.Errorf("expected DER sequence")
	}
	return crlDERChildren(value.Bytes)
}

// crypto/x509 extracts URI names, but ignores DistributionPoint.reasons and
// cRLIssuer. Those raw fields must be checked before using the extracted URLs.
func certificateCRLURLs(cert *x509.Certificate) ([]string, bool, error) {
	var urls []string
	advertised := false
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(crlDistributionPointsOID) {
			continue
		}
		if advertised {
			return nil, true, fmt.Errorf("duplicate CRL Distribution Points extension")
		}
		advertised = true
		points, err := crlDERSequence(extension.Value)
		if err != nil || len(points) == 0 {
			return nil, true, fmt.Errorf("empty or malformed CRL Distribution Points")
		}
		for _, point := range points {
			fields, err := crlDERSequence(point.FullBytes)
			if err != nil {
				return nil, true, err
			}
			lastTag := -1
			for _, field := range fields {
				if field.Class != asn1.ClassContextSpecific || field.Tag <= lastTag || field.Tag > 2 {
					return nil, true, fmt.Errorf("malformed CRL Distribution Point field")
				}
				lastTag = field.Tag
				switch field.Tag {
				case 1:
					return nil, true, fmt.Errorf("reason-partitioned CRL Distribution Point is unsupported")
				case 2:
					return nil, true, fmt.Errorf("indirect CRL Distribution Point (cRLIssuer) is unsupported")
				case 0:
					names, err := crlPointURLs(field)
					if err != nil {
						return nil, true, err
					}
					urls = append(urls, names...)
				}
			}
		}
	}
	return urls, advertised, nil
}

func certificateAdvertisesOCSP(cert *x509.Certificate) (bool, error) {
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(crlAuthorityInfoOID) {
			continue
		}
		descriptions, err := crlDERSequence(extension.Value)
		if err != nil {
			return false, err
		}
		for _, description := range descriptions {
			fields, err := crlDERSequence(description.FullBytes)
			if err != nil || len(fields) != 2 {
				return false, fmt.Errorf("malformed Authority Information Access")
			}
			var method asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(fields[0].FullBytes, &method); err != nil {
				return false, err
			}
			if method.Equal(crlOCSPMethodOID) {
				return true, nil
			}
		}
	}
	return false, nil
}

func crlPointURLs(field asn1.RawValue) ([]string, error) {
	if !field.IsCompound {
		return nil, fmt.Errorf("malformed DistributionPointName")
	}
	name, err := crlDERValue(field.Bytes)
	if err != nil || name.Class != asn1.ClassContextSpecific || name.Tag != 0 || !name.IsCompound {
		return nil, fmt.Errorf("relative or malformed DistributionPointName is unsupported")
	}
	names, err := crlDERChildren(name.Bytes)
	if err != nil {
		return nil, err
	}
	var urls []string
	for _, generalName := range names {
		if generalName.Class != asn1.ClassContextSpecific || generalName.Tag < 0 || generalName.Tag > 8 {
			return nil, fmt.Errorf("malformed GeneralName")
		}
		if generalName.Tag == 6 && !generalName.IsCompound {
			if location, err := canonicalCRLURL(string(generalName.Bytes)); err == nil {
				urls = append(urls, location)
			}
		}
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("DistributionPointName has no usable http(s) URI")
	}
	return urls, nil
}

func checkCRLExtensions(crl *x509.RevocationList) error {
	for _, extension := range crl.Extensions {
		switch {
		case extension.Id.Equal(crlDeltaIndicatorOID):
			return fmt.Errorf("delta CRL is unsupported")
		case oidIn(extension.Id, crlAuthorityKeyIDOID, crlNumberOID, crlIssuingPointOID, crlFreshestOID):
		case extension.Critical:
			return fmt.Errorf("unrecognized critical CRL extension %s", extension.Id)
		}
	}
	for _, entry := range crl.RevokedCertificateEntries {
		for _, extension := range entry.Extensions {
			switch {
			case extension.Id.Equal(crlCertificateIssuerOID):
				return fmt.Errorf("indirect CRL entry (certificateIssuer) is unsupported")
			case oidIn(extension.Id, crlReasonCodeOID, crlInvalidityDateOID):
			case extension.Critical:
				return fmt.Errorf("unrecognized critical CRL entry extension %s", extension.Id)
			}
		}
	}
	return nil
}

// checkCRLScope applies the Issuing Distribution Point of RFC 5280 Section
// 5.2.5. A distribution point name in it must match one of the certificate's
// own distribution point names (Section 6.3.3(b)(2)(i)).
func checkCRLScope(crl *x509.RevocationList, cert *x509.Certificate, distributionPoints []string) error {
	for _, extension := range crl.Extensions {
		if !extension.Id.Equal(crlIssuingPointOID) {
			continue
		}
		fields, err := crlDERSequence(extension.Value)
		if err != nil {
			return fmt.Errorf("malformed Issuing Distribution Point")
		}
		lastTag := -1
		for _, field := range fields {
			if field.Class != asn1.ClassContextSpecific || field.Tag <= lastTag || field.Tag > 5 {
				return fmt.Errorf("malformed Issuing Distribution Point field")
			}
			lastTag = field.Tag
			if field.Tag == 0 {
				urls, err := crlPointURLs(field)
				if err != nil {
					return err
				}
				matched := false
				for _, name := range urls {
					matched = matched || slices.Contains(distributionPoints, name)
				}
				if !matched {
					return fmt.Errorf("CRL scope does not name the certificate distribution point")
				}
				continue
			}
			if field.Tag == 3 {
				return fmt.Errorf("reason-partitioned CRL scope is unsupported")
			}
			if field.IsCompound || len(field.Bytes) != 1 || (field.Bytes[0] != 0 && field.Bytes[0] != 0xff) {
				return fmt.Errorf("malformed Issuing Distribution Point boolean")
			}
			if field.Bytes[0] == 0 {
				continue
			}
			switch field.Tag {
			case 1:
				if cert.IsCA {
					return fmt.Errorf("CRL scope only covers end-entity certificates")
				}
			case 2:
				if !cert.IsCA {
					return fmt.Errorf("CRL scope only covers CA certificates")
				}
			case 4:
				return fmt.Errorf("indirect CRL scope is unsupported")
			case 5:
				return fmt.Errorf("CRL scope only covers attribute certificates")
			}
		}
	}
	return nil
}

// Raw extension decoding is strict: encoding/asn1 struct decoding otherwise
// ignores trailing fields, and crypto/x509 does not reject duplicate CRL OIDs.
func parseCRLExtensions(der []byte) ([]pkix.Extension, error) {
	values, err := crlDERSequence(der)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var extensions []pkix.Extension
	for _, value := range values {
		fields, err := crlDERSequence(value.FullBytes)
		if err != nil || len(fields) < 2 || len(fields) > 3 {
			return nil, fmt.Errorf("malformed CRL extension")
		}
		var extension pkix.Extension
		if _, err := asn1.Unmarshal(fields[0].FullBytes, &extension.Id); err != nil {
			return nil, err
		}
		index := 1
		if len(fields) == 3 {
			if _, err := asn1.Unmarshal(fields[1].FullBytes, &extension.Critical); err != nil {
				return nil, err
			}
			index++
		}
		if _, err := asn1.Unmarshal(fields[index].FullBytes, &extension.Value); err != nil {
			return nil, err
		}
		if seen[extension.Id.String()] {
			return nil, fmt.Errorf("duplicate CRL extension %s", extension.Id)
		}
		seen[extension.Id.String()] = true
		switch {
		case extension.Id.Equal(crlNumberOID):
			var number *big.Int
			rest, err := asn1.Unmarshal(extension.Value, &number)
			if err != nil || len(rest) != 0 || number.Sign() < 0 {
				return nil, fmt.Errorf("malformed CRL number")
			}
		case extension.Id.Equal(crlReasonCodeOID):
			var reason asn1.Enumerated
			rest, err := asn1.Unmarshal(extension.Value, &reason)
			if err != nil || len(rest) != 0 || reason < 0 || reason > 10 || reason == 7 {
				return nil, fmt.Errorf("malformed CRL entry reason code")
			}
		case extension.Id.Equal(crlInvalidityDateOID):
			var invalidityDate time.Time
			rest, err := asn1.UnmarshalWithParams(extension.Value, &invalidityDate, "generalized")
			if err != nil || len(rest) != 0 {
				return nil, fmt.Errorf("malformed CRL entry invalidity date")
			}
		}
		extensions = append(extensions, extension)
	}
	return extensions, nil
}
