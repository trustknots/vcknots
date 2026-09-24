package wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

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

// transactionDataForQuery returns the encoded transaction_data entries whose
// credential_ids contain queryID, preserving request order. It applies the
// OID4VP 1.0 Final Section 5.1 reference filter only: an entry naming several
// credential queries is returned for each of them, so callers that present
// more than one credential must additionally honour the single-use rule with
// assignTransactionDataOwners.
func transactionDataForQuery(encoded []string, queryID string) ([]string, error) {
	var matched []string
	for index, entry := range encoded {
		credentialIDs, err := transactionDataCredentialIDs(entry)
		if err != nil {
			return nil, fmt.Errorf("transaction_data entry %d: %w", index, err)
		}
		if slices.Contains(credentialIDs, queryID) {
			matched = append(matched, entry)
		}
	}
	return matched, nil
}

// assignTransactionDataOwners maps every transaction_data entry to the one
// presented credential query that authorizes it: the first of its
// credential_ids being presented (OID4VP 1.0 Section 5.1, "the Wallet MUST use
// only one of the referenced Credentials"). An entry that references nothing
// presented is invalid_transaction_data (Section 8.4) and fails before any
// credential is serialized.
func assignTransactionDataOwners(encoded []string, presentedQueries []string) (map[string]string, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	selected := make(map[string]bool, len(presentedQueries))
	for _, queryID := range presentedQueries {
		selected[queryID] = true
	}
	owners := make(map[string]string, len(encoded))
	for index, entry := range encoded {
		if _, resolved := owners[entry]; resolved {
			continue
		}
		credentialIDs, err := transactionDataCredentialIDs(entry)
		if err != nil {
			return nil, fmt.Errorf("transaction_data entry %d: %w", index, err)
		}
		owner := ""
		for _, id := range credentialIDs {
			if selected[id] {
				owner = id
				break
			}
		}
		if owner == "" {
			return nil, fmt.Errorf("transaction_data entry %d references no selected credential (invalid_transaction_data)", index)
		}
		owners[entry] = owner
	}
	return owners, nil
}

// ownedTransactionData returns, in request order, the transaction_data entries
// that reference queryID and that assignTransactionDataOwners gave to it.
func ownedTransactionData(encoded []string, queryID string, owners map[string]string) ([]string, error) {
	referenced, err := transactionDataForQuery(encoded, queryID)
	if err != nil {
		return nil, err
	}
	var owned []string
	for _, entry := range referenced {
		if owners[entry] == queryID {
			owned = append(owned, entry)
		}
	}
	return owned, nil
}
