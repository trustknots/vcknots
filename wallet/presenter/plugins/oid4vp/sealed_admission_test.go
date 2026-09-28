package oid4vp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

var (
	sealKey      = bytes.Repeat([]byte{0x5a}, MinSealKeyBytes)
	otherSealKey = bytes.Repeat([]byte{0xa5}, MinSealKeyBytes)
)

// sealedPresenter is a presenter of the fixture under p whose Request Object
// clock reads now.
func (f *requestObjectFixture) sealedPresenter(p profile.Profile, now time.Time) *Oid4vpPresenter {
	validation := f.options()
	validation.Now = func() time.Time { return now }
	return &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &validation, Profile: p}
}

// publish serves claims, signed by the fixture, at /request-object.
func (f *requestObjectFixture) publish(t *testing.T, claims map[string]any) string {
	t.Helper()
	requestObject := f.sign(t, claims, nil)
	f.mu.Lock()
	f.requestObject = []byte(requestObject)
	f.mu.Unlock()
	return requestObject
}

// referenceURI is an Authorization Request that names the fixture's
// request_uri, with method post when post is set.
func (f *requestObjectFixture) referenceURI(clientID string, post bool) string {
	values := url.Values{"client_id": {clientID}, "request_uri": {f.server.URL + "/request-object"}}
	if post {
		values.Set("request_uri_method", "post")
	}
	return "openid4vp://authorize?" + values.Encode()
}

// admitSealed admits claims by reference under p and seals the admission.
func (f *requestObjectFixture) admitSealed(t *testing.T, p *Oid4vpPresenter, claims map[string]any) (*AdmittedRequest, types.SealedAdmission) {
	t.Helper()
	f.publish(t, claims)
	admitted, err := p.ParseRequest(context.Background(), f.referenceURI(claims["client_id"].(string), false))
	require.NoError(t, err)
	handle := admitted.(*AdmittedRequest)
	sealed, err := handle.Seal(sealKey)
	require.NoError(t, err)
	return handle, sealed
}

// TestSealedAdmissionReadmitsUnderHAIP: a HAIP presenter in another call
// (another instance, no shared state) answers a request it admitted by
// reference, while the same Request Object handed over by value stays
// refused (HAIP 1.0 §5.1).
func TestSealedAdmissionReadmitsUnderHAIP(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	first, sealed := f.admitSealed(t, f.sealedPresenter(profile.HAIP(), f.now), claims)
	require.True(t, strings.HasPrefix(string(sealed), "v3."), "the sealed admission is versioned: %q", sealed)

	later := f.sealedPresenter(profile.HAIP(), f.now.Add(time.Minute))
	readmitted, err := later.ReadmitRequest(context.Background(), sealed, sealKey)
	require.NoError(t, err)
	handle := readmitted.(*AdmittedRequest)
	request := handle.Request()
	require.Equal(t, first.Request().Nonce, request.Nonce)
	require.Equal(t, f.clientID(), request.ClientID)
	require.Equal(t, "reference", request.RequestObjectVerification.Delivery)
	require.Equal(t, first.RequestObject(), handle.RequestObject())
	require.Equal(t, first.ResponseEndpoint(), handle.ResponseEndpoint())

	// The re-admitted handle belongs to the presenter that re-admitted it and
	// seals to the same record.
	resealed, err := handle.Seal(sealKey)
	require.NoError(t, err)
	require.Equal(t, sealed, resealed)

	// Without a seal, the Request Object passed by value is refused.
	_, err = later.ParseRequestObject(context.Background(), first.RequestObject(), types.RequestObjectSource{ClientID: f.clientID()})
	require.ErrorIs(t, err, ErrRequestURIRequired)
}

// TestSealedAdmissionUsesTheClockOfTheFirstAdmission: the Request Object is
// authenticated again on the instant of the sealed admission, so consent that
// outlasts exp does not refuse the response; a fresh parse at that time does.
func TestSealedAdmissionUsesTheClockOfTheFirstAdmission(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	_, sealed := f.admitSealed(t, f.sealedPresenter(profile.HAIP(), f.now), claims)

	afterExpiry := f.sealedPresenter(profile.HAIP(), f.now.Add(10*time.Minute))
	readmitted, err := afterExpiry.ReadmitRequest(context.Background(), sealed, sealKey)
	require.NoError(t, err)
	require.Equal(t, f.now.Add(5*time.Minute), readmitted.(*AdmittedRequest).Request().RequestObjectVerification.ExpiresAt)

	_, err = afterExpiry.ParseRequest(context.Background(), f.referenceURI(f.clientID(), false))
	require.Error(t, err, "a fresh parse after exp must fail")
}

// TestSealedAdmissionReplaysTheWalletNonce: a request_uri POST sent a
// wallet_nonce the Request Object echoes; the re-admission checks the echo
// against the sealed nonce without another fetch.
func TestSealedAdmissionReplaysTheWalletNonce(t *testing.T) {
	f := newRequestObjectFixture(t)
	fetches := 0
	f.setRequestObjectHandler(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		require.NoError(t, r.ParseForm())
		claims := f.claims()
		claims["wallet_nonce"] = r.Form.Get("wallet_nonce")
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(f.sign(t, claims, nil)))
	})
	p := f.sealedPresenter(profile.HAIP(), f.now)
	admitted, err := p.ParseRequest(context.Background(), f.referenceURI(f.clientID(), true))
	require.NoError(t, err)
	nonce := admitted.(*AdmittedRequest).Request().RequestObjectVerification.WalletNonce
	require.NotEmpty(t, nonce)
	sealed, err := admitted.(*AdmittedRequest).Seal(sealKey)
	require.NoError(t, err)

	readmitted, err := f.sealedPresenter(profile.HAIP(), f.now).ReadmitRequest(context.Background(), sealed, sealKey)
	require.NoError(t, err)
	require.Equal(t, nonce, readmitted.(*AdmittedRequest).Request().RequestObjectVerification.WalletNonce)
	require.Equal(t, 1, fetches, "the re-admission must not fetch request_uri again")
}

// TestSealedAdmissionRefusesAlteredSeals covers the integrity of the record:
// any change to the record, the tag or the version, or another key, is
// ErrSealedAdmissionInvalid, and nothing is authenticated.
func TestSealedAdmissionRefusesAlteredSeals(t *testing.T) {
	f := newRequestObjectFixture(t)
	_, sealed := f.admitSealed(t, f.sealedPresenter(profile.HAIP(), f.now), f.claims())
	parts := strings.Split(string(sealed), ".")
	require.Len(t, parts, 3)
	record := decodeSealedRecord(t, parts[1])

	withRecord := func(change func(*sealedAdmissionRecord)) types.SealedAdmission {
		altered := record
		change(&altered)
		encoded, err := json.Marshal(altered)
		require.NoError(t, err)
		return types.SealedAdmission(parts[0] + "." + base64.RawURLEncoding.EncodeToString(encoded) + "." + parts[2])
	}
	other := f.sign(t, f.claims(), nil)
	for name, test := range map[string]struct {
		sealed types.SealedAdmission
		key    []byte
	}{
		"another key":              {sealed, otherSealKey},
		"a changed Request Object": {withRecord(func(r *sealedAdmissionRecord) { r.RequestObject = other }), sealKey},
		"a changed wallet_nonce":   {withRecord(func(r *sealedAdmissionRecord) { r.WalletNonce = "chosen" }), sealKey},
		"a changed admission time": {withRecord(func(r *sealedAdmissionRecord) { r.AdmittedAt = time.Now().UTC().Format(time.RFC3339Nano) }), sealKey},
		"a changed profile":        {withRecord(func(r *sealedAdmissionRecord) { r.Profile = profile.VersionDraft24.String() }), sealKey},
		"a changed tag":            {types.SealedAdmission(parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))), sealKey},
		"another version":          {types.SealedAdmission("v1." + parts[1] + "." + parts[2]), sealKey},
		"no version":               {types.SealedAdmission(parts[1] + "." + parts[2]), sealKey},
		"an extra segment":         {sealed + ".x", sealKey},
		"empty":                    {"", sealKey},
	} {
		t.Run(name, func(t *testing.T) {
			fetchesBefore := f.crlRequestCount()
			_, err := f.sealedPresenter(profile.HAIP(), f.now).ReadmitRequest(context.Background(), test.sealed, test.key)
			require.ErrorIs(t, err, ErrSealedAdmissionInvalid)
			require.Equal(t, fetchesBefore, f.crlRequestCount(), "nothing is authenticated before the seal verifies")
		})
	}
}

// TestSealedAdmissionKeyLength: a key shorter than MinSealKeyBytes neither
// seals nor re-admits.
func TestSealedAdmissionKeyLength(t *testing.T) {
	f := newRequestObjectFixture(t)
	handle, sealed := f.admitSealed(t, f.sealedPresenter(profile.HAIP(), f.now), f.claims())
	short := sealKey[:MinSealKeyBytes-1]
	_, err := handle.Seal(short)
	require.ErrorIs(t, err, ErrSealKeyTooShort)
	_, err = f.sealedPresenter(profile.HAIP(), f.now).ReadmitRequest(context.Background(), sealed, short)
	require.ErrorIs(t, err, ErrSealKeyTooShort)
}

// TestSealedAdmissionUnderFinal: a Final presenter seals and re-admits too,
// and a seal is re-admitted only under the profile it was made under.
func TestSealedAdmissionUnderFinal(t *testing.T) {
	f := newRequestObjectFixture(t)
	_, sealed := f.admitSealed(t, f.sealedPresenter(profile.Final(), f.now), f.claims())

	readmitted, err := f.sealedPresenter(profile.Final(), f.now).ReadmitRequest(context.Background(), sealed, sealKey)
	require.NoError(t, err)
	require.Equal(t, "reference", readmitted.(*AdmittedRequest).Request().RequestObjectVerification.Delivery)

	_, err = f.sealedPresenter(profile.HAIP(), f.now).ReadmitRequest(context.Background(), sealed, sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionInvalid, "a Final admission is not a HAIP admission")
	_, err = f.sealedPresenter(profile.Final(), f.now).ReadmitDraft24Request(context.Background(), sealed, sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionInvalid, "an OpenID4VP 1.0 admission is not a Draft 24 admission")
}

// TestSealedAdmissionOnlyForDeliveryByReference: a Request Object passed by
// value, or plain parameters, carry no delivery fact and are not sealable.
func TestSealedAdmissionOnlyForDeliveryByReference(t *testing.T) {
	f := newRequestObjectFixture(t)
	p := f.sealedPresenter(profile.Final(), f.now)
	byValue, err := p.ParseRequestObject(context.Background(), f.sign(t, f.claims(), nil), types.RequestObjectSource{ClientID: f.clientID()})
	require.NoError(t, err)
	_, err = byValue.(*AdmittedRequest).Seal(sealKey)
	require.ErrorIs(t, err, ErrAdmissionNotSealable)

	var nilHandle *AdmittedRequest
	_, err = nilHandle.Seal(sealKey)
	require.ErrorIs(t, err, ErrAdmissionNotSealable)
}

// TestSealedAdmissionUnderDraft24: the Draft 24 entry points seal and
// re-admit the same way.
func TestSealedAdmissionUnderDraft24(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	claims := draft24X509Claims(f)
	f.publish(t, claims)
	p := f.sealedPresenter(profile.Final(), f.now)
	admitted, err := p.ParseDraft24Request(context.Background(), f.referenceURI(draft24X509ClientID, false))
	require.NoError(t, err)
	sealed, err := admitted.(*AdmittedRequest).Seal(sealKey)
	require.NoError(t, err)

	readmitted, err := f.sealedPresenter(profile.Final(), f.now).ReadmitDraft24Request(context.Background(), sealed, sealKey)
	require.NoError(t, err)
	handle := readmitted.(*AdmittedRequest)
	require.True(t, handle.Draft24())
	require.Equal(t, "pd-1", handle.Request().PresentationDefinition.ID)

	_, err = f.sealedPresenter(profile.Final(), f.now).ReadmitRequest(context.Background(), sealed, sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionInvalid, "a Draft 24 admission is not an OpenID4VP 1.0 admission")
}

// TestSealedAdmissionAuthenticatesAgain: the seal carries facts, not trust;
// a certificate revoked since the first admission refuses the re-admission.
func TestSealedAdmissionAuthenticatesAgain(t *testing.T) {
	f := newRequestObjectFixture(t)
	_, sealed := f.admitSealed(t, f.sealedPresenter(profile.HAIP(), f.now), f.claims())
	f.setCRL(t, true)
	_, err := f.sealedPresenter(profile.HAIP(), f.now).ReadmitRequest(context.Background(), sealed, sealKey)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrSealedAdmissionInvalid), "the seal verified; the chain did not: %v", err)
}

func decodeSealedRecord(t *testing.T, body string) sealedAdmissionRecord {
	t.Helper()
	encoded, err := base64.RawURLEncoding.DecodeString(body)
	require.NoError(t, err)
	var record sealedAdmissionRecord
	require.NoError(t, json.Unmarshal(encoded, &record))
	return record
}

func (f *requestObjectFixture) crlRequestCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.crlRequests
}
