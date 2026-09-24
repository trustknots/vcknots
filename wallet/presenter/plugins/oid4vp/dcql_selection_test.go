package oid4vp

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestResolveSatisfiableDCQLCredentials(t *testing.T) {
	query := &DcqlQuery{
		Credentials: []CredentialQuery{
			{
				ID:     "pid",
				Format: "dc+sd-jwt",
				Meta:   map[string]any{"vct_values": []string{"urn:eudi:pid:1"}},
				Claims: []DCQLClaimQuery{
					{Path: []any{"given_name"}},
					{Path: []any{"family_name"}},
				},
			},
		},
	}
	candidates := []DCQLCredentialCandidate{
		{
			ID:     "wallet-credential-1",
			Format: "dc+sd-jwt",
			VCT:    "urn:eudi:pid:1",
			Claims: []string{"given_name", "family_name", "birthdate"},
		},
	}

	selections, err := ResolveSatisfiableDCQLCredentials(query, candidates)
	if err != nil {
		t.Fatalf("ResolveSatisfiableDCQLCredentials() error = %v", err)
	}
	if len(selections) != 1 {
		t.Fatalf("expected one selection, got %#v", selections)
	}
	selection := selections[0]
	if selection.QueryID != "pid" || selection.CandidateID != "wallet-credential-1" {
		t.Fatalf("selection IDs = %#v", selection)
	}
	if got := selection.Claims; len(got) != 2 || got[0] != "given_name" || got[1] != "family_name" {
		t.Fatalf("requested claims = %#v", got)
	}
}

func TestResolveSatisfiableDCQLCredentials_CredentialSets(t *testing.T) {
	required := true
	optional := false
	query := &DcqlQuery{
		Credentials: []CredentialQuery{
			{
				ID:     "pid",
				Format: "dc+sd-jwt",
				Claims: []DCQLClaimQuery{{Path: []any{"given_name"}}},
			},
			{
				ID:     "address",
				Format: "dc+sd-jwt",
				Claims: []DCQLClaimQuery{{Path: []any{"street_address"}}},
			},
			{
				ID:     "optional_email",
				Format: "dc+sd-jwt",
				Claims: []DCQLClaimQuery{{Path: []any{"email"}}},
			},
		},
		CredentialSets: []CredentialSetQuery{
			{Required: &required, Options: [][]string{{"pid", "address"}, {"pid"}}},
			{Required: &optional, Options: [][]string{{"optional_email"}}},
		},
	}
	candidates := []DCQLCredentialCandidate{
		{ID: "wallet-pid", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"given_name"}},
	}

	selections, err := ResolveSatisfiableDCQLCredentials(query, candidates)
	if err != nil {
		t.Fatalf("ResolveSatisfiableDCQLCredentials() error = %v", err)
	}
	if len(selections) != 1 || selections[0].QueryID != "pid" {
		t.Fatalf("expected required fallback option to select pid only, got %#v", selections)
	}
}

func TestResolveSatisfiableDCQLCredentials_RequiredCredentialSetFailure(t *testing.T) {
	query := &DcqlQuery{
		Credentials: []CredentialQuery{
			{
				ID:     "pid",
				Format: "dc+sd-jwt",
				Claims: []DCQLClaimQuery{{Path: []any{"given_name"}}},
			},
		},
		CredentialSets: []CredentialSetQuery{
			{Options: [][]string{{"pid"}}},
		},
	}

	_, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{
		{ID: "wallet-pid", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"family_name"}},
	})
	if err == nil {
		t.Fatal("expected required credential_set failure")
	}
}

func TestResolveDCQLClaimSetPreference(t *testing.T) {
	query, err := parseDcqlQuery(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"id":"age","path":["age_over_18"],"values":[true]},{"id":"birth","path":["birthdate"]}],"claim_sets":[["age"],["birth"]]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name              string
		candidates        []DCQLCredentialCandidate
		wantID, wantClaim string
	}{
		{"first available option discloses only age", []DCQLCredentialCandidate{{ID: "both", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"age_over_18", "birthdate"}, ClaimValues: map[string]any{"age_over_18": true}}}, "both", "age_over_18"},
		{"fallback after value mismatch", []DCQLCredentialCandidate{{ID: "both", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"age_over_18", "birthdate"}, ClaimValues: map[string]any{"age_over_18": false}}}, "both", "birthdate"},
		{"fallback after missing claim", []DCQLCredentialCandidate{{ID: "birth", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"birthdate"}}}, "birth", "birthdate"},
		{"preferred option across candidates", []DCQLCredentialCandidate{{ID: "birth", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"birthdate"}}, {ID: "age", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"age_over_18"}, ClaimValues: map[string]any{"age_over_18": true}}}, "age", "age_over_18"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected, err := ResolveSatisfiableDCQLCredentials(query, tc.candidates)
			if err != nil || len(selected) != 1 {
				t.Fatalf("selection = %#v, %v", selected, err)
			}
			if selected[0].CandidateID != tc.wantID || !reflect.DeepEqual(selected[0].Claims, []string{tc.wantClaim}) {
				t.Fatalf("selection = %#v, want %s / %s", selected, tc.wantID, tc.wantClaim)
			}
		})
	}
	selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{{ID: "pid", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"age_over_18"}, ClaimValues: map[string]any{"age_over_18": false}}})
	if err == nil || len(selected) != 0 {
		t.Fatalf("unsatisfied claim sets returned a credential: %#v, %v", selected, err)
	}
}

func TestResolveDCQLEmptyClaimSetFallback(t *testing.T) {
	typed := &DcqlQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt",
		Claims:    []DCQLClaimQuery{{ID: "age", Path: []any{"age_over_18"}, Values: []any{true}}},
		ClaimSets: [][]string{{"age"}, {}},
	}}}
	parsed, err := parseDcqlQuery(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"id":"age","path":["age_over_18"],"values":[true]}],"claim_sets":[["age"],[]]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []struct {
		name  string
		query *DcqlQuery
	}{{"typed", typed}, {"raw", parsed}} {
		for _, ageOver18 := range []bool{true, false} {
			name := "empty fallback"
			wantClaims := []string{}
			if ageOver18 {
				name = "preferred age claim"
				wantClaims = []string{"age_over_18"}
			}
			t.Run(source.name+"/"+name, func(t *testing.T) {
				selected, err := ResolveSatisfiableDCQLCredentials(source.query, []DCQLCredentialCandidate{{
					ID: "identity", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"age_over_18", "birthdate"},
					ClaimValues: map[string]any{"age_over_18": ageOver18, "birthdate": "2000-01-01"},
				}})
				if err != nil || len(selected) != 1 {
					t.Fatalf("claim set selection = %#v, %v", selected, err)
				}
				if !reflect.DeepEqual(selected[0].Claims, wantClaims) {
					t.Fatalf("selected claims = %#v, want %#v", selected[0].Claims, wantClaims)
				}
			})
		}
	}
}

func TestResolveDCQLValuesRequireExactPrimitiveMatch(t *testing.T) {
	for _, tc := range []struct {
		name             string
		actual, expected any
		match            bool
	}{
		{"string", "Alice", "Alice", true},
		{"string case differs", "ALICE", "Alice", false},
		{"number is not string", 18, "18", false},
		{"string is not number", "18", 18, false},
		{"boolean", true, true, true},
		{"boolean differs", false, true, false},
		{"number is not boolean", 1, true, false},
		{"boolean is not number", true, 1, false},
		{"decoded integer", float64(18), 18, true},
		{"int64", int64(18), json.Number("18"), true},
		{"uint64", uint64(18446744073709551615), json.Number("18446744073709551615"), true},
		{"large integer exact", json.Number("9007199254740993"), json.Number("9007199254740993"), true},
		{"large integers do not round", json.Number("9007199254740992"), json.Number("9007199254740993"), false},
		{"rounded float cannot prove original integer", float64(9007199254740993), json.Number("9007199254740992"), false},
		{"rounded float32 cannot prove original integer", float32(16777217), json.Number("16777216"), false},
		{"fractional actual", 18.5, 18, false},
		{"object actual", map[string]any{"age": 18}, 18, false},
		{"null actual", nil, 18, false},
		{"float32", float32(18), 18, true},
		{"NaN", math.NaN(), 18, false},
		{"infinity", math.Inf(1), 18, false},
		{"negative zero", json.Number("-0.0"), 0, true},
		{"integer exponent", json.Number("18e3"), 18000, true},
		{"integer decimal", json.Number("18.000"), 18, true},
		{"huge exponent stays symbolic", json.Number("10e999999999"), json.Number("1e1000000000"), true},
		{"small fractional exponent", json.Number("1e-1000000000"), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := &DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{Path: []any{"value"}, Values: []any{tc.expected}}}}}}
			candidates := []DCQLCredentialCandidate{{ID: "value", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"value"}, ClaimValues: map[string]any{"value": tc.actual}}}
			selected, err := ResolveSatisfiableDCQLCredentials(query, candidates)
			if tc.match {
				if err != nil || len(selected) != 1 {
					t.Fatalf("matching value rejected: %#v, %v", selected, err)
				}
			} else if err == nil || len(selected) != 0 {
				t.Fatalf("nonmatching value disclosed: %#v, %v", selected, err)
			}
		})
	}
}

func TestResolveDCQLMissingValueFailsClosed(t *testing.T) {
	query := &DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{Path: []any{"name"}, Values: []any{"Alice", "Bob"}}}}}}
	candidate := DCQLCredentialCandidate{ID: "pid", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"name"}}
	if selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{candidate}); err == nil || len(selected) != 0 {
		t.Fatalf("claim name alone satisfied value restriction: %#v, %v", selected, err)
	}
	candidate.ClaimValues = map[string]any{"name": "Bob"}
	if selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{candidate}); err != nil || len(selected) != 1 {
		t.Fatalf("second expected value did not match: %#v, %v", selected, err)
	}
}

func TestResolveDCQLRequiredQueriesAreAtomic(t *testing.T) {
	query := &DcqlQuery{Credentials: []CredentialQuery{{ID: "available", Format: "dc+sd-jwt"}, {ID: "missing", Format: "jwt_vc_json"}}}
	selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{{ID: "pid", Format: "dc+sd-jwt"}})
	if err == nil || len(selected) != 0 {
		t.Fatalf("incomplete required query set returned credentials: %#v, %v", selected, err)
	}
}

func TestResolveDCQLValidatesDirectCallerConstraints(t *testing.T) {
	optional := false
	for _, tc := range []struct {
		name  string
		query DcqlQuery
	}{
		{"duplicate query id", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}, {ID: "pid", Format: "dc+sd-jwt"}}}},
		{"invalid query id", DcqlQuery{Credentials: []CredentialQuery{{ID: "bad id", Format: "dc+sd-jwt"}}}},
		{"empty claims", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{}}}}},
		{"empty values", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{Path: []any{"name"}, Values: []any{}}}}}}},
		{"fractional value", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{Path: []any{"name"}, Values: []any{1.5}}}}}}},
		{"missing path", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{ID: "n"}}}}}},
		{"missing claim id", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{Path: []any{"name"}}}, ClaimSets: [][]string{{"n"}}}}}},
		{"duplicate claim id", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{ID: "n", Path: []any{"name"}}, {ID: "n", Path: []any{"birth"}}}}}}},
		{"empty claim sets", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", ClaimSets: [][]string{}}}}},
		{"claim sets without claims", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", ClaimSets: [][]string{{"n"}}}}}},
		{"empty claim set without claims", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", ClaimSets: [][]string{{}}}}}},
		{"null claim set", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{ID: "n", Path: []any{"name"}}}, ClaimSets: [][]string{nil}}}}},
		{"empty credential sets", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}}, CredentialSets: []CredentialSetQuery{}}},
		{"empty optional credential option", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}}, CredentialSets: []CredentialSetQuery{{Required: &optional, Options: [][]string{{}}}}}},
		{"unknown optional credential reference", DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}}, CredentialSets: []CredentialSetQuery{{Required: &optional, Options: [][]string{{"unknown"}}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected, err := ResolveSatisfiableDCQLCredentials(&tc.query, []DCQLCredentialCandidate{{ID: "pid", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"name"}}})
			if err == nil || len(selected) != 0 {
				t.Fatalf("invalid constraints returned credentials: %#v, %v", selected, err)
			}
		})
	}
}

func TestResolveDCQLNestedClaimDoesNotBecomeRootClaim(t *testing.T) {
	query, err := parseDcqlQuery(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["address","name"]}]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{{ID: "pid", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"name", "address"}}})
	if err == nil || len(selected) != 0 {
		t.Fatalf("unsupported path returned credentials: %#v, %v", selected, err)
	}
}

func TestResolveDCQLRepeatedClaimPathDisclosesOnce(t *testing.T) {
	query := &DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{Path: []any{"name"}}, {Path: []any{"name"}}}}}}
	selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{{ID: "pid", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"name"}}})
	if err != nil || len(selected) != 1 || !reflect.DeepEqual(selected[0].Claims, []string{"name"}) {
		t.Fatalf("duplicate claim paths were not deduplicated: %#v, %v", selected, err)
	}
}

// dcqlSelectionQueryJSON is the request the caller-chosen selection tests
// validate against. "pid" offers two claim sets, so the choice between them is
// the Holder's; "addr" completes the larger option of the required
// credential_set; "email" is requested but belongs to no credential_set.
const dcqlSelectionQueryJSON = `{"credentials":[` +
	`{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:pid"]},` +
	`"claims":[{"id":"given","path":["given_name"]},{"id":"family","path":["family_name"]}],` +
	`"claim_sets":[["given","family"],["family"]]},` +
	`{"id":"addr","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:address"]},"claims":[{"path":["street_address"]}]},` +
	`{"id":"email","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:email"]},"claims":[{"path":["email"]}]}],` +
	`"credential_sets":[{"options":[["pid","addr"],["pid"]]},{"options":[["addr"]],"required":false}]}`

// TestValidateDCQLMatches covers the decision OID4VP 1.0 Sections
// 6.2 and 6.3 leave to the Wallet and this library leaves to the Holder: which
// claim set to disclose and which credential_set option to answer. The library
// accepts any choice the request itself accepts, and nothing else.
func TestValidateDCQLMatches(t *testing.T) {
	query, err := parseDcqlQuery(dcqlSelectionQueryJSON)
	if err != nil {
		t.Fatal(err)
	}
	unbound := false
	candidates := []DCQLCredentialCandidate{
		{ID: "pid-1", Format: "dc+sd-jwt", VCT: "urn:test:pid", Claims: []string{"given_name", "family_name"}},
		{ID: "addr-1", Format: "dc+sd-jwt", VCT: "urn:test:address", Claims: []string{"street_address"}},
		{ID: "email-1", Format: "dc+sd-jwt", VCT: "urn:test:email", Claims: []string{"email"}},
		{ID: "pid-unbound", Format: "dc+sd-jwt", VCT: "urn:test:pid", Claims: []string{"given_name", "family_name"}, HolderBound: &unbound},
		{ID: "pid-jwt", Format: "jwt_vc_json", VCT: "urn:test:pid", Claims: []string{"given_name", "family_name"}},
	}
	for _, tc := range []struct {
		name            string
		selections      []DCQLMatch
		wantUnsatisfied bool
	}{
		{name: "holder picks the narrower claim set", selections: []DCQLMatch{
			{QueryID: "pid", CandidateID: "pid-1", Claims: []string{"family_name"}},
		}},
		{name: "holder picks the wider claim set in any order", selections: []DCQLMatch{
			{QueryID: "pid", CandidateID: "pid-1", Claims: []string{"family_name", "given_name"}},
		}},
		{name: "holder answers the wider credential_set option", selections: []DCQLMatch{
			{QueryID: "pid", CandidateID: "pid-1", Claims: []string{"family_name"}},
			{QueryID: "addr", CandidateID: "addr-1", Claims: []string{"street_address"}},
		}},
		{name: "claims outside every claim set", wantUnsatisfied: true, selections: []DCQLMatch{
			{QueryID: "pid", CandidateID: "pid-1", Claims: []string{"given_name"}},
		}},
		{name: "credential query the request does not contain", wantUnsatisfied: true, selections: []DCQLMatch{
			{QueryID: "phone", CandidateID: "pid-1", Claims: []string{"family_name"}},
		}},
		{name: "credential the wallet cannot present", wantUnsatisfied: true, selections: []DCQLMatch{
			{QueryID: "pid", CandidateID: "not-stored", Claims: []string{"family_name"}},
		}},
		{name: "vct the credential query does not accept", wantUnsatisfied: true, selections: []DCQLMatch{
			{QueryID: "pid", CandidateID: "addr-1", Claims: []string{"family_name"}},
		}},
		{name: "format the credential query does not request", wantUnsatisfied: true, selections: []DCQLMatch{
			{QueryID: "pid", CandidateID: "pid-jwt", Claims: []string{"family_name"}},
		}},
		{name: "credential without the required holder binding", wantUnsatisfied: true, selections: []DCQLMatch{
			{QueryID: "pid", CandidateID: "pid-unbound", Claims: []string{"family_name"}},
		}},
		{name: "no option of the required credential_set is answered", wantUnsatisfied: true, selections: []DCQLMatch{
			{QueryID: "addr", CandidateID: "addr-1", Claims: []string{"street_address"}},
		}},
		{name: "credential query outside every answered option", wantUnsatisfied: true, selections: []DCQLMatch{
			{QueryID: "pid", CandidateID: "pid-1", Claims: []string{"family_name"}},
			{QueryID: "email", CandidateID: "email-1", Claims: []string{"email"}},
		}},
		{name: "selecting nothing leaves the required credential_set unanswered", wantUnsatisfied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDCQLMatches(query, candidates, tc.selections)
			if tc.wantUnsatisfied {
				if !errors.Is(err, ErrDCQLSelectionUnsatisfied) {
					t.Fatalf("error = %v, want ErrDCQLSelectionUnsatisfied", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateDCQLMatches() error = %v", err)
			}
		})
	}
}

// TestValidateDCQLMatches_PerQueryConstraints covers the
// constraints a single credential query places on how many credentials answer
// it (OID4VP 1.0 Section 6.1 multiple) and on who issued them (Section 6.1.1
// trusted_authorities).
func TestValidateDCQLMatches_PerQueryConstraints(t *testing.T) {
	query, err := parseDcqlQuery(`{"credentials":[` +
		`{"id":"multi","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"multiple":true,"claims":[{"path":["given_name"]}],` +
		`"trusted_authorities":[{"type":"aki","values":["authority-a"]}]},` +
		`{"id":"single","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}],` +
		`"credential_sets":[{"options":[["multi"]],"required":false},{"options":[["single"]],"required":false}]}`)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []DCQLCredentialCandidate{
		{ID: "a1", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"given_name"}, AuthorityKeyIDs: []string{"authority-a"}},
		{ID: "a2", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"given_name"}, AuthorityKeyIDs: []string{"authority-a"}},
		{ID: "b1", Format: "dc+sd-jwt", VCT: "urn:test:identity", Claims: []string{"given_name"}, AuthorityKeyIDs: []string{"authority-b"}},
	}
	for _, tc := range []struct {
		name            string
		selections      []DCQLMatch
		wantUnsatisfied bool
	}{
		{name: "several credentials answer a multiple query", selections: []DCQLMatch{
			{QueryID: "multi", CandidateID: "a1", Claims: []string{"given_name"}},
			{QueryID: "multi", CandidateID: "a2", Claims: []string{"given_name"}},
		}},
		{name: "the same credential is selected twice", wantUnsatisfied: true, selections: []DCQLMatch{
			{QueryID: "multi", CandidateID: "a1", Claims: []string{"given_name"}},
			{QueryID: "multi", CandidateID: "a1", Claims: []string{"given_name"}},
		}},
		{name: "a second credential answers a single-credential query", wantUnsatisfied: true, selections: []DCQLMatch{
			{QueryID: "single", CandidateID: "a1", Claims: []string{"given_name"}},
			{QueryID: "single", CandidateID: "a2", Claims: []string{"given_name"}},
		}},
		{name: "credential outside the trusted authorities", wantUnsatisfied: true, selections: []DCQLMatch{
			{QueryID: "multi", CandidateID: "b1", Claims: []string{"given_name"}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDCQLMatches(query, candidates, tc.selections)
			if tc.wantUnsatisfied {
				if !errors.Is(err, ErrDCQLSelectionUnsatisfied) {
					t.Fatalf("error = %v, want ErrDCQLSelectionUnsatisfied", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateDCQLMatches() error = %v", err)
			}
		})
	}
}

// TestValidateDCQLMatches_MalformedQuery pins that a request this
// library cannot interpret is reported as a structural failure, not as a
// rejected consent decision: no selection could have repaired it.
func TestValidateDCQLMatches_MalformedQuery(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query *DcqlQuery
	}{
		{name: "no query at all"},
		{name: "no credential queries", query: &DcqlQuery{}},
		{name: "duplicate credential query ids", query: &DcqlQuery{Credentials: []CredentialQuery{
			{ID: "pid", Format: "dc+sd-jwt"}, {ID: "pid", Format: "dc+sd-jwt"},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDCQLMatches(tc.query, nil, nil)
			if err == nil {
				t.Fatal("expected a structural error")
			}
			if errors.Is(err, ErrDCQLSelectionUnsatisfied) {
				t.Fatalf("malformed request reported as an unsatisfied selection: %v", err)
			}
		})
	}
}

// OID4VP 1.0 Appendix B.1.1: every type of one type_values alternative must be
// among the credential's types, and Section 6.4.2 treats a credential that does
// not match as absent. The W3C base context term VerifiableCredential expands
// to its IRI; other terms are compared as written.
func TestResolveDCQLTypeValues(t *testing.T) {
	query, err := parseDcqlQuery(`{"credentials":[{"id":"id","format":"jwt_vc_json",` +
		`"meta":{"type_values":[["https://www.w3.org/2018/credentials#VerifiableCredential","IDCredential"],["AlumniCredential"]]}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		types     []string
		wantMatch bool
	}{
		{name: "every type of the first alternative", types: []string{"VerifiableCredential", "IDCredential"}, wantMatch: true},
		{name: "second alternative with extra types", types: []string{"VerifiableCredential", "AlumniCredential", "Other"}, wantMatch: true},
		{name: "part of an alternative", types: []string{"IDCredential"}},
		{name: "no listed type", types: []string{"VerifiableCredential", "OtherCredential"}},
		{name: "no types at all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := DCQLCredentialCandidate{ID: "vc", Format: "jwt_vc_json", Types: tc.types}
			selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{candidate})
			validateErr := ValidateDCQLMatches(query, []DCQLCredentialCandidate{candidate},
				[]DCQLMatch{{QueryID: "id", CandidateID: "vc", Claims: []string{}}})
			if tc.wantMatch {
				if err != nil || len(selected) != 1 || validateErr != nil {
					t.Fatalf("selection = %#v, %v; validation = %v", selected, err, validateErr)
				}
				return
			}
			if !errors.Is(err, ErrDCQLSelectionUnsatisfied) || len(selected) != 0 {
				t.Fatalf("non-matching types returned a credential: %#v, %v", selected, err)
			}
			if !errors.Is(validateErr, ErrDCQLSelectionUnsatisfied) {
				t.Fatalf("validation error = %v, want ErrDCQLSelectionUnsatisfied", validateErr)
			}
		})
	}
}

// OID4VP 1.0 Section 6.4.1: an element whose value does not match values is
// treated as absent, so a null component resolves to the index of each match
// instead of disclosing every element.
func TestResolveDCQLValuesNarrowWildcards(t *testing.T) {
	candidate := DCQLCredentialCandidate{ID: "pid", Format: "dc+sd-jwt", VCT: "urn:test:identity", ClaimObject: map[string]any{
		"nationalities": []any{"JP", "DE", "FR"},
		"degrees":       []any{map[string]any{"type": "Master"}, map[string]any{"type": "Bachelor"}},
	}}
	for _, tc := range []struct {
		name  string
		claim DCQLClaimQuery
		want  []string
	}{
		{name: "one match", claim: DCQLClaimQuery{Path: []any{"nationalities", nil}, Values: []any{"DE"}}, want: []string{`["nationalities",1]`}},
		{name: "several matches", claim: DCQLClaimQuery{Path: []any{"nationalities", nil}, Values: []any{"FR", "JP"}}, want: []string{`["nationalities",0]`, `["nationalities",2]`}},
		{name: "nested wildcard", claim: DCQLClaimQuery{Path: []any{"degrees", nil, "type"}, Values: []any{"Bachelor"}}, want: []string{`["degrees",1,"type"]`}},
		{name: "no values keeps the wildcard", claim: DCQLClaimQuery{Path: []any{"nationalities", nil}}, want: []string{`["nationalities",null]`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := &DcqlQuery{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{tc.claim}}}}
			selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{candidate})
			if err != nil || len(selected) != 1 {
				t.Fatalf("selection = %#v, %v", selected, err)
			}
			if !reflect.DeepEqual(selected[0].Claims, tc.want) {
				t.Fatalf("requested claims = %q, want %q", selected[0].Claims, tc.want)
			}
		})
	}
}

// ResolveDCQLClaimSets lists the satisfiable claim sets in the Verifier's
// order, so a Holder's choice can be made among them.
func TestResolveDCQLClaimSets(t *testing.T) {
	query := &DcqlQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt",
		Claims: []DCQLClaimQuery{
			{ID: "age", Path: []any{"age_over_18"}},
			{ID: "birth", Path: []any{"birthdate"}},
			{ID: "missing", Path: []any{"not_available"}},
		},
		ClaimSets: [][]string{{"missing"}, {"age"}, {"birth", "age"}},
	}}}
	candidate := DCQLCredentialCandidate{ID: "c", Format: "dc+sd-jwt", Claims: []string{"age_over_18", "birthdate"}}

	sets, err := ResolveDCQLClaimSets(query, "pid", candidate)
	if err != nil || !reflect.DeepEqual(sets, [][]string{{"age_over_18"}, {"birthdate", "age_over_18"}}) {
		t.Fatalf("claim sets = %q, %v", sets, err)
	}
	for name, run := range map[string]func() error{
		"unknown query": func() error { _, err := ResolveDCQLClaimSets(query, "other", candidate); return err },
		"wrong format": func() error {
			_, err := ResolveDCQLClaimSets(query, "pid", DCQLCredentialCandidate{ID: "c", Format: "jwt_vc_json"})
			return err
		},
		"no claim set held": func() error {
			_, err := ResolveDCQLClaimSets(query, "pid", DCQLCredentialCandidate{ID: "c", Format: "dc+sd-jwt"})
			return err
		},
	} {
		if err := run(); !errors.Is(err, ErrDCQLSelectionUnsatisfied) {
			t.Fatalf("%s: error = %v, want ErrDCQLSelectionUnsatisfied", name, err)
		}
	}
}
