package oid4vp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// Sealed admissions.
//
// A Wallet asks the Holder for consent between admitting a request and
// answering it. An integrator whose calls are stateless cannot keep the
// *AdmittedRequest across that gap, and parsing the Request Object again as a
// Request Object passed by value is refused where the profile requires
// delivery by reference (HAIP 1.0 §5.1, Options.RequireSignedRequestByReference):
// only a fetch by this library establishes that delivery.
//
// A sealed admission carries that fact across the gap without weakening the
// rule. Seal records what the first admission observed - the Request Object
// as fetched, the request_uri it was fetched from, the delivery by reference,
// the wallet_nonce the library sent for it, the outer client_id, the instant
// it was authenticated at, the profile it was admitted under (its text form,
// which names every option) and, for a Draft 24 request, the Presentation
// Definition it fetched from presentation_definition_uri - and seals the
// record with HMAC-SHA256 under a key only the caller holds.
// ReadmitRequest (and ReadmitDraft24Request) accept the record only when the
// seal verifies under that key, the profile is the presenter's, and the
// record is younger than MaxReadmitAge. They then
// apply RequestURIPolicy to the recorded request_uri and authenticate the
// Request Object again: its signature, the client authentication its Client
// Identifier Prefix selects, the wallet_nonce echo and every profile option.
// The Request Object's exp, iat and nbf are judged on the clock of the first
// admission; the certificate chain, its revocation, a Verifier Attestation and
// a Trust Chain on the current clock. A Request Object handed over by value
// without a seal is refused exactly as before. Nothing on the wire changes:
// the Verifier sees one request_uri fetch and one response.
//
// A seal is a bearer token for its key's holder, and the library keeps no
// state: the same sealed value re-admits any number of times until
// MaxReadmitAge. A wallet that answers each request once sets
// ConsumeSealedAdmission, which the re-admission calls with the seal's
// identifier before it returns.
//
// The record is versioned: "v3." followed by the base64url JSON record and
// the base64url HMAC-SHA256 tag, separated by ".". The tag covers a label
// naming the version and the record, so a record is never read under a
// version it was not sealed for. Both parts must be canonical unpadded
// base64url.

// MinSealKeyBytes is the shortest key Seal and the re-admission methods
// accept: the output length of SHA-256, below which RFC 2104 Section 3
// discourages HMAC keys.
const MinSealKeyBytes = 32

// DefaultMaxReadmitAge is how long after the first admission a sealed
// admission is re-admitted when Oid4vpPresenter.MaxReadmitAge is zero.
const DefaultMaxReadmitAge = 15 * time.Minute

const (
	sealedAdmissionVersion = "v3"
	// sealedAdmissionLabel is MACed before the record, so a tag made for
	// another purpose or another version under the same key never verifies.
	sealedAdmissionLabel = "vcknots/oid4vp/sealed-admission/v3"
	// maxSealedAdmissionBytes bounds a sealed admission before it is decoded:
	// a record holds at most one bounded Request Object.
	maxSealedAdmissionBytes = 2 * maxRequestObjectBytes

	sealedWireOpenID4VP1 = "openid4vp-1.0"
	sealedWireDraft24    = "openid4vp-draft-24"
)

var (
	// ErrSealKeyTooShort reports a sealing key shorter than MinSealKeyBytes.
	ErrSealKeyTooShort = common.NewCodedError("sealed_admission_key_too_short", "the sealed admission key is shorter than 32 bytes")
	// ErrAdmissionNotSealable reports a handle whose admission cannot be
	// sealed: its Request Object did not come from a request_uri fetch by this
	// library (it was passed by value, or the request was plain parameters or
	// a Digital Credentials API invocation). Such a request has no delivery
	// fact to carry; a caller keeps its Request Object or parameters instead.
	ErrAdmissionNotSealable = common.NewCodedError("admission_not_sealable", "only a Request Object the presenter fetched from request_uri can be sealed")
	// ErrSealedAdmissionInvalid reports a sealed admission that is not
	// accepted: malformed, of an unknown version, altered, sealed under
	// another key, recorded for another protocol version or profile than
	// the re-admission runs under, older than MaxReadmitAge, or
	// admitted at an instant after the presenter's clock.
	ErrSealedAdmissionInvalid = common.NewCodedError("sealed_admission_invalid", "the sealed admission is malformed, altered, sealed with another key, recorded for another profile or expired")
	// ErrSealedAdmissionConsumed reports that Oid4vpPresenter.ConsumeSealedAdmission
	// refused a re-admission, which it does for a seal it has seen before.
	ErrSealedAdmissionConsumed = common.NewCodedError("sealed_admission_consumed", "the sealed admission was already consumed")
)

// sealedAdmissionRecord is the sealed JSON record.
type sealedAdmissionRecord struct {
	Wire string `json:"wire"`
	// Profile is the text form of the profile the request was admitted under
	// (profile.Profile.String), which names every option, so
	// profile.Final().With(profile.HAIPOptions()) and profile.Final() are told
	// apart and a new option never changes how an old record reads.
	Profile       string `json:"profile"`
	Delivery      string `json:"delivery"`
	RequestURI    string `json:"request_uri"`
	ClientID      string `json:"client_id"`
	WalletNonce   string `json:"wallet_nonce,omitempty"`
	AdmittedAt    string `json:"admitted_at"`
	RequestObject string `json:"request_object"`
	// PresentationDefinitionURI and PresentationDefinition are the
	// presentation_definition_uri of a Draft 24 Request Object and the
	// Presentation Definition fetched from it, exactly as served (Draft 24
	// §5.5). The re-admission uses the definition only for the same URI in
	// the re-authenticated Request Object, and does not fetch it again.
	PresentationDefinitionURI string `json:"presentation_definition_uri,omitempty"`
	PresentationDefinition    string `json:"presentation_definition,omitempty"`
}

var (
	_ types.RequestReadmitter        = (*Oid4vpPresenter)(nil)
	_ types.Draft24RequestReadmitter = (*Oid4vpPresenter)(nil)
)

// Seal returns the sealed record of this admission under key, for a caller
// that answers the request in a later, stateless call. The record holds the
// Request Object as fetched, the request_uri it was fetched from, the
// delivery by reference, the wallet_nonce sent for it, the outer client_id,
// the instant it was authenticated at (for a re-admitted handle, that of the
// first admission), the profile it was admitted under and the Presentation
// Definition resolved from a presentation_definition_uri, and is sealed with
// HMAC-SHA256. ReadmitRequest (or ReadmitDraft24Request) accepts it only under
// the same key, so a profile that requires delivery by reference (HAIP 1.0
// §5.1) still refuses a Request Object handed over by value without a seal.
//
// Only a request whose Request Object this library fetched from request_uri
// can be sealed (ErrAdmissionNotSealable). key must hold at least
// MinSealKeyBytes bytes (ErrSealKeyTooShort); the caller keeps it secret and
// hands the same key to the re-admission.
//
// The record contains the Request Object, which is readable to whoever holds
// the sealed value; the seal protects its integrity, not its confidentiality.
func (r *AdmittedRequest) Seal(key []byte) (types.SealedAdmission, error) {
	if len(key) < MinSealKeyBytes {
		return "", ErrSealKeyTooShort
	}
	if r == nil || r.req == nil || r.admission.source != sourceReference || r.admission.requestURI == "" || r.requestObject == "" || r.admission.admittedAt.IsZero() {
		return "", ErrAdmissionNotSealable
	}
	record := sealedAdmissionRecord{
		Wire:          sealedWireName(r.wire),
		Profile:       r.admission.profile,
		Delivery:      sourceReference.delivery(),
		RequestURI:    r.admission.requestURI,
		ClientID:      r.admission.outerClientID,
		WalletNonce:   r.admission.walletNonce,
		AdmittedAt:    r.admission.admittedAt.UTC().Format(time.RFC3339Nano),
		RequestObject: r.requestObject,
	}
	if definition := r.admission.resolvedDefinition; definition != nil {
		record.PresentationDefinitionURI = definition.uri
		record.PresentationDefinition = definition.body
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("failed to encode the sealed admission: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(encoded)
	tag := base64.RawURLEncoding.EncodeToString(sealedAdmissionTag(key, body))
	return types.SealedAdmission(sealedAdmissionVersion + "." + body + "." + tag), nil
}

// ReadmitRequest re-admits an OpenID4VP 1.0 request from a sealed admission
// (see AdmittedRequest.Seal). The seal must verify under key, name this
// presenter's profile, and be younger than MaxReadmitAge. RequestURIPolicy is applied to the recorded request_uri, and
// the Request Object is authenticated again as the one this library fetched
// from it, with the wallet_nonce it sent. Its exp, iat and nbf are judged on
// the clock of the first admission, so an exp that passed since then does not
// refuse it (RequestObjectVerification.ExpiresAt reports it); every trust
// check - the certificate chain and its revocation, a Verifier Attestation, a
// Trust Chain - runs again on the current clock. The same seal re-admits
// again unless ConsumeSealedAdmission refuses it. The result is an
// *AdmittedRequest, which can be sealed again (to the same record).
func (p *Oid4vpPresenter) ReadmitRequest(ctx context.Context, sealed types.SealedAdmission, key []byte) (types.AdmittedRequest, error) {
	return asAdmitted(p.readmitRequest(ctx, sealed, key))
}

// ReadmitDraft24Request is ReadmitRequest for a Draft 24 request.
func (p *Oid4vpPresenter) ReadmitDraft24Request(ctx context.Context, sealed types.SealedAdmission, key []byte) (types.AdmittedRequest, error) {
	return asAdmitted(p.readmitDraft24Request(ctx, sealed, key))
}

func (p *Oid4vpPresenter) readmitRequest(ctx context.Context, sealed types.SealedAdmission, key []byte) (*AdmittedRequest, error) {
	if _, err := p.profileOptions(); err != nil {
		return nil, err
	}
	opened, err := p.openSealedAdmission(sealed, key, wireOpenID4VP1)
	if err != nil {
		return nil, err
	}
	record := opened.record
	builder, err := p.newRequestBuilder(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := parseOID4VPClientID(record.ClientID); err != nil {
		return nil, fmt.Errorf("%w: the sealed client_id is not an OpenID4VP 1.0 Client Identifier: %w", ErrSealedAdmissionInvalid, err)
	}
	builder.expectedClientID = record.ClientID
	if err := builder.replayReference(opened); err != nil {
		return nil, err
	}
	builder.withRequestObject(record.RequestObject)
	return p.finishReadmission(ctx, opened, func() (*AdmittedRequest, error) {
		return p.finishParse(&builder.requestCore, builder.Build, wireOpenID4VP1)
	})
}

func (p *Oid4vpPresenter) readmitDraft24Request(ctx context.Context, sealed types.SealedAdmission, key []byte) (*AdmittedRequest, error) {
	if _, err := p.profileOptions(); err != nil {
		return nil, err
	}
	opened, err := p.openSealedAdmission(sealed, key, wireDraft24)
	if err != nil {
		return nil, err
	}
	record := opened.record
	builder, err := p.newDraft24RequestBuilder(ctx)
	if err != nil {
		return nil, err
	}
	if record.ClientID != "" {
		if _, err := parseDraft24ClientID(record.ClientID); err != nil {
			return nil, fmt.Errorf("%w: the sealed client_id is not a Draft 24 Client Identifier: %w", ErrSealedAdmissionInvalid, err)
		}
	}
	builder.expectedClientID = record.ClientID
	if err := builder.replayReference(opened); err != nil {
		return nil, err
	}
	if record.PresentationDefinitionURI != "" {
		builder.sealedDefinition = &resolvedDefinition{uri: record.PresentationDefinitionURI, body: record.PresentationDefinition}
	}
	builder.withRequestObject(record.RequestObject)
	return p.finishReadmission(ctx, opened, func() (*AdmittedRequest, error) {
		return p.finishParse(&builder.requestCore, builder.Build, wireDraft24)
	})
}

// finishReadmission runs the re-admission parse and, when it admits the
// request, hands the seal to ConsumeSealedAdmission. The hook runs last, so a
// seal is consumed only by a re-admission that succeeded.
func (p *Oid4vpPresenter) finishReadmission(ctx context.Context, opened *openedSeal, parse func() (*AdmittedRequest, error)) (*AdmittedRequest, error) {
	handle, err := parse()
	if err != nil {
		return nil, err
	}
	if p.ConsumeSealedAdmission != nil {
		if err := p.ConsumeSealedAdmission(ctx, opened.id, opened.notAfter); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrSealedAdmissionConsumed, err)
		}
	}
	return handle, nil
}

// replayReference sets up a parse to authenticate a sealed Request Object as
// the one fetched from the recorded request_uri, with the wallet_nonce sent
// for it and its claims judged at the instant of the sealed admission. The
// recorded request_uri passes RequestURIPolicy first, as a fetch would.
func (c *requestCore) replayReference(opened *openedSeal) error {
	if err := c.applyRequestURIPolicy(opened.record.RequestURI); err != nil {
		return err
	}
	c.requestSource = sourceReference
	c.requestURI = opened.record.RequestURI
	c.sentWalletNonce = opened.record.WalletNonce
	c.readmitAt = opened.admittedAt
	return nil
}

// openedSeal is a sealed admission whose seal verified.
type openedSeal struct {
	record     *sealedAdmissionRecord
	admittedAt time.Time
	// id identifies the seal to ConsumeSealedAdmission: the base64url tag,
	// which only the key's holder can produce.
	id string
	// notAfter is the instant the seal stops re-admitting (admittedAt +
	// MaxReadmitAge), after which a consumed-seal record can be dropped.
	notAfter time.Time
}

// maxReadmitAge is MaxReadmitAge, or DefaultMaxReadmitAge when it is zero.
func (p *Oid4vpPresenter) maxReadmitAge() time.Duration {
	if p.MaxReadmitAge > 0 {
		return p.MaxReadmitAge
	}
	return DefaultMaxReadmitAge
}

// readmitClock is the presenter's current Request Object clock.
func (p *Oid4vpPresenter) readmitClock() (time.Time, time.Duration) {
	if p.RequestObjectValidation != nil {
		return requestObjectNow(*p.RequestObjectValidation), p.RequestObjectValidation.ClockSkew
	}
	return time.Now(), 0
}

// openSealedAdmission verifies sealed under key and returns its record, which
// must be for wire, for the profile this presenter admits wire under, and
// younger than MaxReadmitAge.
func (p *Oid4vpPresenter) openSealedAdmission(sealed types.SealedAdmission, key []byte, wire wireContract) (*openedSeal, error) {
	if len(key) < MinSealKeyBytes {
		return nil, ErrSealKeyTooShort
	}
	if p.MaxReadmitAge < 0 {
		return nil, fmt.Errorf("%w: MaxReadmitAge cannot be negative", common.ErrInvalidInput)
	}
	invalid := func(reason string) (*openedSeal, error) {
		return nil, fmt.Errorf("%w: %s", ErrSealedAdmissionInvalid, reason)
	}
	if len(sealed) > maxSealedAdmissionBytes {
		return invalid("the sealed admission is too large")
	}
	version, rest, found := strings.Cut(string(sealed), ".")
	if !found || version != sealedAdmissionVersion {
		return invalid("the sealed admission is not of version " + sealedAdmissionVersion)
	}
	body, encodedTag, found := strings.Cut(rest, ".")
	if !found || strings.Contains(encodedTag, ".") {
		return invalid("the sealed admission is malformed")
	}
	// Strict: a tag or record with non-zero padding bits is not the
	// canonical encoding of the bytes it decodes to, and is refused rather
	// than read as another spelling of a sealed value.
	tag, err := base64.RawURLEncoding.Strict().DecodeString(encodedTag)
	if err != nil || !hmac.Equal(tag, sealedAdmissionTag(key, body)) {
		return invalid("the seal does not verify under this key")
	}
	encoded, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil {
		return invalid("the sealed record is not base64url")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record sealedAdmissionRecord
	if err := decoder.Decode(&record); err != nil {
		return invalid("the sealed record is not a " + sealedAdmissionVersion + " record")
	}
	switch {
	case record.Wire != sealedWireName(wire):
		return invalid(fmt.Sprintf("the admission was sealed for %s, not %s", record.Wire, sealedWireName(wire)))
	case record.Profile != p.admissionProfile(wire).String():
		return invalid(fmt.Sprintf("the admission was sealed under the profile %q, not %q", record.Profile, p.admissionProfile(wire)))
	case wire != wireDraft24 && record.PresentationDefinitionURI != "":
		return invalid("an OpenID4VP 1.0 admission carries no Presentation Definition")
	case record.Delivery != sourceReference.delivery():
		return invalid("the sealed Request Object was not delivered by reference")
	case record.RequestURI == "":
		return invalid("the sealed record carries no request_uri")
	case record.RequestObject == "":
		return invalid("the sealed record carries no Request Object")
	}
	admittedAt, err := time.Parse(time.RFC3339Nano, record.AdmittedAt)
	if err != nil || admittedAt.IsZero() {
		return invalid("the sealed admission time is malformed")
	}
	now, skew := p.readmitClock()
	notAfter := admittedAt.Add(p.maxReadmitAge())
	switch {
	case admittedAt.After(now.Add(skew)):
		return invalid("the sealed admission time is after the presenter's clock")
	case now.After(notAfter):
		return invalid(fmt.Sprintf("the admission is older than MaxReadmitAge (%s)", p.maxReadmitAge()))
	}
	return &openedSeal{record: &record, admittedAt: admittedAt, id: encodedTag, notAfter: notAfter}, nil
}

// sealedAdmissionTag is the HMAC-SHA256 tag of a v1 record body under key.
func sealedAdmissionTag(key []byte, body string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(sealedAdmissionLabel))
	mac.Write([]byte{0})
	mac.Write([]byte(body))
	return mac.Sum(nil)
}

// sealedWireName names a wire contract in a sealed record.
func sealedWireName(wire wireContract) string {
	if wire == wireDraft24 {
		return sealedWireDraft24
	}
	return sealedWireOpenID4VP1
}

// admissionProfile is the profile p admits a request of wire under:
// profile.Draft24() for the Draft 24 contract, which the presenter's profile
// does not apply to, and the presenter's profile otherwise.
func (p *Oid4vpPresenter) admissionProfile(wire wireContract) profile.Profile {
	if wire == wireDraft24 {
		return profile.Draft24()
	}
	return p.Profile
}
