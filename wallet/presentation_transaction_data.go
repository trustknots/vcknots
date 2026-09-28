package wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
)

// This guard enforces OID4VP B.3.3 for the queries referenced by transaction
// data. Validation of supported transaction types is a separate policy.
func validateTransactionDataHolderBinding(req *oid4vp.CredentialPresentationRequest) error {
	if len(req.TransactionData) == 0 {
		return nil
	}
	if req.DcqlQuery == nil {
		return fmt.Errorf("transaction_data requires dcql_query")
	}
	queries := make(map[string]oid4vp.CredentialQuery, len(req.DcqlQuery.Credentials))
	for _, query := range req.DcqlQuery.Credentials {
		queries[query.ID] = query
	}
	for _, encoded := range req.TransactionData {
		credentialIDs, err := transactionDataCredentialIDs(encoded)
		if err != nil {
			return err
		}
		for _, id := range credentialIDs {
			query, known := queries[id]
			if !known {
				return fmt.Errorf("transaction_data references unknown credential query %q", id)
			}
			if query.Format == "dc+sd-jwt" && !query.RequiresHolderBinding() {
				return fmt.Errorf("transaction_data requires cryptographic holder binding for credential query %q", id)
			}
		}
	}
	return nil
}

// transactionDataCredentialIDs decodes the credential_ids array of one
// base64url-encoded transaction_data entry. OID4VP 1.0 Final Section 5.1
// defines it as "REQUIRED. Non-empty array of strings each referencing a
// Credential requested by the Verifier that can be used to authorize this
// transaction. The string matches the id field in the DCQL Credential Query."
func transactionDataCredentialIDs(encoded string) ([]string, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction_data encoding: %w", err)
	}
	var data struct {
		CredentialIDs []string `json:"credential_ids"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("invalid transaction_data object: %w", err)
	}
	if len(data.CredentialIDs) == 0 {
		return nil, fmt.Errorf("transaction_data.credential_ids must not be empty")
	}
	return data.CredentialIDs, nil
}

// Transaction data assignment conditions (OpenID4VP 1.0 Sections 5.1 and 8.4,
// Draft 24 Section 5.1).
var (
	// ErrTransactionDataAssignmentRequired reports a transaction_data entry
	// that more than one presented credential could authorize, with no
	// CredentialSelection.TransactionData saying which: several credentials
	// answering the one credential query it references (multiple: true). The
	// library does not pick one for the Holder, and does not bind the
	// transaction into every one of them.
	ErrTransactionDataAssignmentRequired = common.NewCodedError("transaction_data_assignment_required", "a transaction_data entry can be authorized by several presented credentials; assign it with CredentialSelection.TransactionData")
	// ErrTransactionDataAssignmentInvalid reports a
	// CredentialSelection.TransactionData the request does not accept: an
	// index outside the request's transaction_data, a credential that answers
	// none of the credential queries the entry references, an entry assigned
	// to credentials of two different referenced queries ("the Wallet MUST use
	// only one of the referenced Credentials"), or an entry no presented
	// credential authorizes (Section 8.4: the presentation MUST include it).
	ErrTransactionDataAssignmentInvalid = common.NewCodedError("transaction_data_assignment_invalid", "the transaction_data assignment does not satisfy the request")
)

// transactionDataAssignment is, for each selection, the indexes of the
// transaction_data entries each of its presentations carries, keyed by the
// credential query (or input descriptor) the presentation answers, in request
// order.
type transactionDataAssignment []map[string][]int

// carried returns the entries the presentation of selection answering query
// carries, in request order.
func (a transactionDataAssignment) carried(selection int, query string, encoded []string) []string {
	var entries []string
	for _, index := range a[selection][query] {
		entries = append(entries, encoded[index])
	}
	return entries
}

// selectionEntries returns, in request order, every entry any presentation of
// selection carries: a Draft 24 SD-JWT VC is one presentation whatever the
// input descriptors it answers.
func (a transactionDataAssignment) selectionEntries(selection int, encoded []string) []string {
	var indexes []int
	for _, owned := range a[selection] {
		indexes = append(indexes, owned...)
	}
	slices.Sort(indexes)
	var entries []string
	for _, index := range slices.Compact(indexes) {
		entries = append(entries, encoded[index])
	}
	return entries
}

// assignTransactionData decides which presentation carries each
// transaction_data entry, before anything is serialized.
//
// When a selection sets CredentialSelection.TransactionData, the Holder's
// assignment is used as given: each index names an entry the credential
// authorizes, carried by the presentation of the first credential query in
// the entry's credential_ids that the credential answers. Every entry must be
// assigned (Section 8.4), and the credentials an entry is assigned to must
// answer one and the same referenced query (Section 5.1: "the Wallet MUST use
// only one of the referenced Credentials"); several credentials of that one
// query each carry it only because the assignment names each of them.
//
// Otherwise each entry goes to the first query of its credential_ids that is
// presented; when several presented credentials answer that query, the entry
// is ErrTransactionDataAssignmentRequired rather than bound into all of them.
func assignTransactionData(encoded []string, selections []CredentialSelection) (transactionDataAssignment, error) {
	assignment := make(transactionDataAssignment, len(selections))
	for index := range assignment {
		assignment[index] = map[string][]int{}
	}
	explicit := false
	for _, selection := range selections {
		if selection.TransactionData != nil {
			explicit = true
		}
	}
	if len(encoded) == 0 {
		if explicit {
			for _, selection := range selections {
				if len(selection.TransactionData) > 0 {
					return nil, fmt.Errorf("%w: the request carries no transaction_data", ErrTransactionDataAssignmentInvalid)
				}
			}
		}
		return assignment, nil
	}
	referenced := make([][]string, len(encoded))
	for index, entry := range encoded {
		ids, err := transactionDataCredentialIDs(entry)
		if err != nil {
			return nil, fmt.Errorf("transaction_data entry %d: %w", index, err)
		}
		referenced[index] = ids
	}
	holders := make([][]int, len(encoded))
	query := make([]string, len(encoded))
	// settle chooses the query that carries entry: the first of its
	// credential_ids that every credential it is assigned to answers, so the
	// entry is authorized through one referenced query only (Section 5.1).
	settle := func(entry int) error {
		for _, id := range referenced[entry] {
			answeredByAll := true
			for _, selection := range holders[entry] {
				if !slices.Contains(selections[selection].QueryIDs, id) {
					answeredByAll = false
					break
				}
			}
			if answeredByAll {
				query[entry] = id
				return nil
			}
		}
		return fmt.Errorf("%w: transaction_data[%d] references %v, and no one of them is answered by every credential it is assigned to; only one of the referenced credentials may authorize it", ErrTransactionDataAssignmentInvalid, entry, referenced[entry])
	}
	assign := func(entry, selection int) error {
		if !slices.ContainsFunc(referenced[entry], func(id string) bool { return slices.Contains(selections[selection].QueryIDs, id) }) {
			return fmt.Errorf("%w: transaction_data[%d] references %v, which the credential of selection %d does not answer", ErrTransactionDataAssignmentInvalid, entry, referenced[entry], selection)
		}
		holders[entry] = append(holders[entry], selection)
		return nil
	}
	if explicit {
		for selectionIndex, selection := range selections {
			seen := map[int]bool{}
			for _, entry := range selection.TransactionData {
				if entry < 0 || entry >= len(encoded) {
					return nil, fmt.Errorf("%w: selection %d names transaction_data[%d], the request carries %d", ErrTransactionDataAssignmentInvalid, selectionIndex, entry, len(encoded))
				}
				if seen[entry] {
					return nil, fmt.Errorf("%w: selection %d names transaction_data[%d] twice", ErrTransactionDataAssignmentInvalid, selectionIndex, entry)
				}
				seen[entry] = true
				if err := assign(entry, selectionIndex); err != nil {
					return nil, err
				}
			}
		}
		for entry := range encoded {
			if len(holders[entry]) == 0 {
				return nil, fmt.Errorf("%w: transaction_data[%d] is authorized by no presented credential (invalid_transaction_data)", ErrTransactionDataAssignmentInvalid, entry)
			}
			if err := settle(entry); err != nil {
				return nil, err
			}
		}
	} else {
		for entry := range encoded {
			owner, candidates := "", []int{}
			for _, id := range referenced[entry] {
				for selectionIndex, selection := range selections {
					if slices.Contains(selection.QueryIDs, id) {
						candidates = append(candidates, selectionIndex)
					}
				}
				if len(candidates) > 0 {
					owner = id
					break
				}
			}
			switch {
			case owner == "":
				return nil, fmt.Errorf("transaction_data entry %d references no selected credential (invalid_transaction_data)", entry)
			case len(candidates) > 1:
				return nil, fmt.Errorf("%w: transaction_data[%d] references the query %q, which %d presented credentials answer", ErrTransactionDataAssignmentRequired, entry, owner, len(candidates))
			}
			holders[entry] = candidates
			query[entry] = owner
		}
	}
	for entry := range encoded {
		for _, selection := range holders[entry] {
			assignment[selection][query[entry]] = append(assignment[selection][query[entry]], entry)
		}
	}
	return assignment, nil
}
