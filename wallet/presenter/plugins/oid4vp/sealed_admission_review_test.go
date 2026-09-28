package oid4vp

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// withMaxReadmitAge is p with MaxReadmitAge set.
func withMaxReadmitAge(p *Oid4vpPresenter, age time.Duration) *Oid4vpPresenter {
	p.MaxReadmitAge = age
	return p
}

// The CRL is reissued after the first admission, so its thisUpdate is after
// the sealed instant. Revocation is judged on the current clock, which such a
// CRL is valid on, not on the clock of the first admission, which would
// refuse it as not yet valid.
func TestSealedAdmissionChecksRevocationOnTheCurrentClock(t *testing.T) {
	f := newRequestObjectFixture(t)
	_, sealed := f.admitSealed(t, f.sealedPresenter(profile.HAIP(), f.now), f.claims())
	later := f.now.Add(31 * time.Minute)
	list := &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: f.now.Add(30 * time.Minute), NextUpdate: f.now.Add(2 * time.Hour)}
	der, err := x509.CreateRevocationList(rand.Reader, list, f.root, f.rootKey)
	require.NoError(t, err)
	f.mu.Lock()
	f.crl = der
	f.mu.Unlock()

	readmitted, err := withMaxReadmitAge(f.sealedPresenter(profile.HAIP(), later), time.Hour).ReadmitRequest(context.Background(), sealed, sealKey)
	require.NoError(t, err)
	// exp (f.now+5m) passed, and is still judged at the sealed instant.
	require.Equal(t, f.now.Add(5*time.Minute), readmitted.(*AdmittedRequest).Request().RequestObjectVerification.ExpiresAt)
}

// The leaf certificate expired between the admission and the
// re-admission. The chain is validated on the current clock and refuses it;
// the default MaxReadmitAge refuses the seal before that.
func TestSealedAdmissionChecksTheChainOnTheCurrentClock(t *testing.T) {
	f := newRequestObjectFixture(t)
	_, sealed := f.admitSealed(t, f.sealedPresenter(profile.HAIP(), f.now), f.claims())
	afterLeafExpiry := f.now.Add(72 * time.Hour) // the leaf's NotAfter is f.now+1h

	_, err := withMaxReadmitAge(f.sealedPresenter(profile.HAIP(), afterLeafExpiry), 100*time.Hour).ReadmitRequest(context.Background(), sealed, sealKey)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrSealedAdmissionInvalid), "the seal is valid; the chain is not: %v", err)
	require.ErrorContains(t, err, "certificate chain is not trusted")

	_, err = f.sealedPresenter(profile.HAIP(), afterLeafExpiry).ReadmitRequest(context.Background(), sealed, sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionInvalid)
	require.ErrorContains(t, err, "older than MaxReadmitAge")
}

func TestSealedAdmissionMaxReadmitAge(t *testing.T) {
	f := newRequestObjectFixture(t)
	_, sealed := f.admitSealed(t, f.sealedPresenter(profile.HAIP(), f.now), f.claims())

	_, err := f.sealedPresenter(profile.HAIP(), f.now.Add(DefaultMaxReadmitAge)).ReadmitRequest(context.Background(), sealed, sealKey)
	require.NoError(t, err, "a seal re-admits up to MaxReadmitAge")
	_, err = f.sealedPresenter(profile.HAIP(), f.now.Add(DefaultMaxReadmitAge+time.Second)).ReadmitRequest(context.Background(), sealed, sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionInvalid)

	_, err = withMaxReadmitAge(f.sealedPresenter(profile.HAIP(), f.now.Add(2*time.Minute)), time.Minute).ReadmitRequest(context.Background(), sealed, sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionInvalid, "a shorter MaxReadmitAge applies")

	_, err = withMaxReadmitAge(f.sealedPresenter(profile.HAIP(), f.now), -time.Second).ReadmitRequest(context.Background(), sealed, sealKey)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrSealedAdmissionInvalid))

	// A record whose admission instant is after the presenter's clock, even
	// under the right key, is refused: it would extend the seal's life.
	parts := strings.Split(string(sealed), ".")
	record := decodeSealedRecord(t, parts[1])
	record.AdmittedAt = f.now.Add(time.Hour).Format(time.RFC3339Nano)
	_, err = f.sealedPresenter(profile.HAIP(), f.now).ReadmitRequest(context.Background(), resealRecord(t, record), sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionInvalid)
	require.ErrorContains(t, err, "after the presenter's clock")
}

// resealRecord seals record under sealKey, as a holder of the key could.
func resealRecord(t *testing.T, record sealedAdmissionRecord) types.SealedAdmission {
	t.Helper()
	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	body := base64.RawURLEncoding.EncodeToString(encoded)
	return types.SealedAdmission(sealedAdmissionVersion + "." + body + "." + base64.RawURLEncoding.EncodeToString(sealedAdmissionTag(sealKey, body)))
}

// A seal made under profile.Final().With(profile.HAIPOptions()) must not be
// re-admitted under plain profile.Final(), whose version it shares, which
// would drop every HAIP option. The record carries the profile's text form,
// which names every option.
func TestSealedAdmissionBindsTheProfileOptions(t *testing.T) {
	f := newRequestObjectFixture(t)
	strict, err := profile.Final().With(profile.HAIPOptions())
	require.NoError(t, err)
	_, strictSeal := f.admitSealed(t, f.sealedPresenter(strict, f.now), f.claims())
	_, err = f.sealedPresenter(profile.Final(), f.now).ReadmitRequest(context.Background(), strictSeal, sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionInvalid)
	require.ErrorContains(t, err, `sealed under the profile "haip", not "final"`)
	_, err = f.sealedPresenter(strict, f.now).ReadmitRequest(context.Background(), strictSeal, sealKey)
	require.NoError(t, err)

	_, plainSeal := f.admitSealed(t, f.sealedPresenter(profile.Final(), f.now), f.claims())
	_, err = f.sealedPresenter(strict, f.now).ReadmitRequest(context.Background(), plainSeal, sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionInvalid)

	record := decodeSealedRecord(t, strings.Split(string(strictSeal), ".")[1])
	require.Equal(t, "haip", record.Profile)

	// A profile that is neither preset spells out its options, so a seal
	// never re-admits under a profile that differs in one option.
	strictResponse, err := profile.Final().With(profile.Options{RequireDirectPostJWT: true})
	require.NoError(t, err)
	_, strictResponseSeal := f.admitSealed(t, f.sealedPresenter(strictResponse, f.now), f.claims())
	require.Equal(t, "final;RequireDirectPostJWT", decodeSealedRecord(t, strings.Split(string(strictResponseSeal), ".")[1]).Profile)
	_, err = f.sealedPresenter(profile.Final(), f.now).ReadmitRequest(context.Background(), strictResponseSeal, sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionInvalid)
}

// A tag or record spelled with non-zero padding bits decodes, under the
// lenient decoder, to the same bytes as the canonical spelling; the strict
// decoder refuses it, so each sealed value has exactly one spelling.
func TestSealedAdmissionRequiresCanonicalBase64URL(t *testing.T) {
	f := newRequestObjectFixture(t)
	_, sealed := f.admitSealed(t, f.sealedPresenter(profile.HAIP(), f.now), f.claims())
	parts := strings.Split(string(sealed), ".")
	tag := parts[2]
	require.Len(t, tag, 43, "a 32-byte tag is 43 unpadded characters, the last carrying two padding bits")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, tag[42])
	require.Zero(t, last&3, "the canonical spelling has zero padding bits")
	variant := tag[:42] + string(alphabet[last|1])
	decoded, err := base64.RawURLEncoding.DecodeString(variant)
	require.NoError(t, err)
	canonical, err := base64.RawURLEncoding.DecodeString(tag)
	require.NoError(t, err)
	require.Equal(t, canonical, decoded, "the lenient decoder reads both spellings alike")

	_, err = f.sealedPresenter(profile.HAIP(), f.now).ReadmitRequest(context.Background(), types.SealedAdmission(parts[0]+"."+parts[1]+"."+variant), sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionInvalid)
}

// The request_uri is sealed, and RequestURIPolicy is applied to it on
// re-admission as it was before the fetch.
func TestSealedAdmissionAppliesRequestURIPolicy(t *testing.T) {
	f := newRequestObjectFixture(t)
	_, sealed := f.admitSealed(t, f.sealedPresenter(profile.HAIP(), f.now), f.claims())
	record := decodeSealedRecord(t, strings.Split(string(sealed), ".")[1])
	require.Equal(t, f.server.URL+"/request-object", record.RequestURI)

	var seen [2]string
	refusing := f.sealedPresenter(profile.HAIP(), f.now)
	refusing.RequestObjectValidation.RequestURIPolicy = func(clientID, requestURI string) error {
		seen = [2]string{clientID, requestURI}
		return errors.New("not this verifier's")
	}
	fetches := f.crlRequestCount()
	_, err := refusing.ReadmitRequest(context.Background(), sealed, sealKey)
	require.ErrorIs(t, err, ErrRequestURINotAssociated)
	require.Equal(t, [2]string{f.clientID(), record.RequestURI}, seen)
	require.Equal(t, fetches, f.crlRequestCount(), "refused before the Request Object is authenticated")

	accepting := f.sealedPresenter(profile.HAIP(), f.now)
	accepting.RequestObjectValidation.RequestURIPolicy = func(string, string) error { return nil }
	readmitted, err := accepting.ReadmitRequest(context.Background(), sealed, sealKey)
	require.NoError(t, err)
	resealed, err := readmitted.(*AdmittedRequest).Seal(sealKey)
	require.NoError(t, err)
	require.Equal(t, sealed, resealed, "the re-admitted handle keeps the request_uri and the first admission's instant")
}

// ConsumeSealedAdmission makes a seal single-use; without it, the same seal
// re-admits until MaxReadmitAge (documented).
func TestSealedAdmissionConsumeHook(t *testing.T) {
	f := newRequestObjectFixture(t)
	_, sealed := f.admitSealed(t, f.sealedPresenter(profile.HAIP(), f.now), f.claims())

	plain := f.sealedPresenter(profile.HAIP(), f.now)
	for range 2 {
		_, err := plain.ReadmitRequest(context.Background(), sealed, sealKey)
		require.NoError(t, err, "without the hook a seal re-admits again")
	}

	var mu sync.Mutex
	consumed := map[string]time.Time{}
	once := f.sealedPresenter(profile.HAIP(), f.now.Add(time.Minute))
	once.ConsumeSealedAdmission = func(_ context.Context, id string, notAfter time.Time) error {
		mu.Lock()
		defer mu.Unlock()
		if _, seen := consumed[id]; seen {
			return errors.New("seen")
		}
		consumed[id] = notAfter
		return nil
	}

	// A re-admission that fails does not consume the seal.
	f.setCRL(t, true)
	_, err := once.ReadmitRequest(context.Background(), sealed, sealKey)
	require.Error(t, err)
	require.Empty(t, consumed)
	f.setCRL(t, false)

	_, err = once.ReadmitRequest(context.Background(), sealed, sealKey)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	for id, notAfter := range consumed {
		require.Equal(t, strings.Split(string(sealed), ".")[2], id)
		require.Equal(t, f.now.Add(DefaultMaxReadmitAge), notAfter)
	}
	_, err = once.ReadmitRequest(context.Background(), sealed, sealKey)
	require.ErrorIs(t, err, ErrSealedAdmissionConsumed)
}
