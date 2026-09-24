package federation

import (
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// TrustAnchor is one Trust Anchor this Wallet accepts (OpenID Federation 1.0
// Section 1.2): its Entity Identifier and the Federation Entity Keys the
// Wallet obtained for it out of band. The Trust Anchor's own Entity
// Configuration must verify with these keys; keys the anchor publishes about
// itself are never trusted on their own.
type TrustAnchor struct {
	EntityID string
	JWKS     jose.JSONWebKeySet
}

// TrustChain is a validated Trust Chain (OpenID Federation 1.0 Section 4):
// the subject's Entity Configuration first, then the Subordinate Statements up
// the hierarchy, and the Trust Anchor's Entity Configuration last.
type TrustChain struct {
	// SubjectEntityID is the Entity the chain is about.
	SubjectEntityID string
	// TrustAnchorEntityID is the configured Trust Anchor the chain ends at.
	TrustAnchorEntityID string
	// ExpiresAt is the earliest exp of the statements (Section 10.4), in UTC.
	ExpiresAt time.Time
	// Statements are the verified Entity Statements in chain order.
	Statements []EntityStatement
}

// ValidateTrustChain validates an ordered Trust Chain of compact Entity
// Statements for subjectEntityID against the configured Trust Anchors at now
// (OpenID Federation 1.0 Section 10.2). It checks every statement's claims and
// validity window, the issuer/subject topology, the constraints of Section
// 6.2, that the last statement is a configured Trust Anchor's self-signed
// Entity Configuration, and every signature: the subject's Entity
// Configuration with its own keys and with the keys its superior published
// about it, each Subordinate Statement with its issuer's keys, and the Trust
// Anchor's Entity Configuration with both its own and the configured keys.
//
// iat and exp are compared with now exactly, with no clock skew allowance.
func ValidateTrustChain(trustChain []string, subjectEntityID string, anchors []TrustAnchor, now time.Time) (*TrustChain, error) {
	if len(trustChain) == 0 {
		return nil, failure(ErrTrustChainInvalid, "trust chain must contain at least one statement")
	}
	statements := make([]*decodedStatement, 0, len(trustChain))
	for _, raw := range trustChain {
		statement, err := decodeEntityStatement(raw)
		if err != nil {
			return nil, err
		}
		statements = append(statements, statement)
	}
	subject, anchorStatement := statements[0], statements[len(statements)-1]

	if err := checkStatementTimestamps(statements, now); err != nil {
		return nil, err
	}
	if subject.Issuer != subjectEntityID || subject.Subject != subjectEntityID {
		return nil, failure(ErrTrustChainInvalid, "trust chain subject does not match")
	}
	for i := 0; i < len(statements)-1; i++ {
		if statements[i].Issuer != statements[i+1].Subject {
			return nil, failure(ErrTrustChainInvalid, "trust chain topology is invalid")
		}
	}
	if err := checkTrustChainConstraints(statements); err != nil {
		return nil, err
	}
	if anchorStatement.isSubordinate() {
		return nil, failure(ErrTrustChainInvalid, "trust anchor statement must be self-issued")
	}
	anchorIndex := slices.IndexFunc(anchors, func(anchor TrustAnchor) bool { return anchor.EntityID == anchorStatement.Issuer })
	if anchorIndex < 0 {
		return nil, failure(ErrTrustChainInvalid, "trust anchor is not configured")
	}
	anchor := anchors[anchorIndex]

	if err := verifyStatementSignature(subject.raw, subject.JWKS); err != nil {
		return nil, err
	}
	for i := 0; i < len(statements)-1; i++ {
		if err := verifyStatementSignature(statements[i].raw, statements[i+1].JWKS); err != nil {
			return nil, err
		}
	}
	if err := verifyStatementSignature(anchorStatement.raw, anchorStatement.JWKS); err != nil {
		return nil, err
	}
	if err := verifyStatementSignature(anchorStatement.raw, anchor.JWKS); err != nil {
		return nil, err
	}

	chain := &TrustChain{
		SubjectEntityID:     subject.Subject,
		TrustAnchorEntityID: anchor.EntityID,
		Statements:          make([]EntityStatement, len(statements)),
	}
	for i, statement := range statements {
		chain.Statements[i] = statement.EntityStatement
		if i == 0 || statement.ExpiresAt.Before(chain.ExpiresAt) {
			chain.ExpiresAt = statement.ExpiresAt
		}
	}
	return chain, nil
}

// checkStatementTimestamps refuses a statement issued after now or expired at
// or before now. There is deliberately no clock skew allowance.
func checkStatementTimestamps(statements []*decodedStatement, now time.Time) error {
	nowSeconds := now.Unix()
	for _, statement := range statements {
		if statement.issuedAtSeconds > nowSeconds {
			return failure(ErrTrustChainInvalid, "entity statement is not active yet")
		}
		if statement.expiresAtSeconds <= nowSeconds {
			return failure(ErrTrustChainInvalid, "entity statement has expired")
		}
	}
	return nil
}

// checkTrustChainConstraints applies the constraints of every Subordinate
// Statement above the subject (OpenID Federation 1.0 Section 6.2) to the part
// of the chain below it.
func checkTrustChainConstraints(statements []*decodedStatement) error {
	for i := 1; i < len(statements); i++ {
		statement := statements[i]
		if !statement.isSubordinate() || statement.Constraints == nil {
			continue
		}
		if err := checkMaxPathLength(statement.Constraints, i); err != nil {
			return err
		}
		if err := checkNamingConstraints(statement.Constraints, statements[:i+1]); err != nil {
			return err
		}
		if _, present := statement.Constraints["allowed_entity_types"]; present {
			if _, ok := asNonEmptyStringArray(statement.Constraints["allowed_entity_types"]); !ok {
				return failure(ErrTrustChainInvalid, "allowed_entity_types must be a string array")
			}
		}
	}
	return nil
}

// checkMaxPathLength applies Section 6.2.1: max_path_length is "the maximum
// number of Intermediate Entities between the Entity setting the constraint
// and the Trust Chain subject". The statement at statementIndex sits above
// statementIndex-1 Intermediate Entities.
func checkMaxPathLength(constraints map[string]any, statementIndex int) error {
	value, present := constraints["max_path_length"]
	if !present {
		return nil
	}
	maxPathLength, ok := jsonInteger(value)
	if !ok || maxPathLength < 0 {
		return failure(ErrTrustChainInvalid, "constraints max_path_length must be a non-negative integer")
	}
	if int64(statementIndex-1) > maxPathLength {
		return failure(ErrTrustChainInvalid, "trust chain violates max_path_length constraint")
	}
	return nil
}

// checkNamingConstraints applies Section 6.2.2 to the Entity Identifiers of
// the statements below the constraining one: each host must fall inside a
// permitted subtree when any is listed, and inside no excluded subtree.
func checkNamingConstraints(constraints map[string]any, below []*decodedStatement) error {
	value, present := constraints["naming_constraints"]
	if !present {
		return nil
	}
	naming, ok := asObject(value)
	if !ok {
		return failure(ErrTrustChainInvalid, "naming_constraints must be an object")
	}
	permitted, err := optionalConstraintStrings(naming, "permitted")
	if err != nil {
		return err
	}
	excluded, err := optionalConstraintStrings(naming, "excluded")
	if err != nil {
		return err
	}
	for _, statement := range below {
		host, err := entityIdentifierHost(statement.Subject)
		if err != nil {
			return err
		}
		if permitted != nil && !slices.ContainsFunc(permitted, func(subtree string) bool { return hostInNameSubtree(host, subtree) }) {
			return failure(ErrTrustChainInvalid, "trust chain violates naming_constraints")
		}
		if slices.ContainsFunc(excluded, func(subtree string) bool { return hostInNameSubtree(host, subtree) }) {
			return failure(ErrTrustChainInvalid, "trust chain violates naming_constraints")
		}
	}
	return nil
}

func optionalConstraintStrings(naming map[string]any, name string) ([]string, error) {
	value, present := naming[name]
	if !present {
		return nil, nil
	}
	values, ok := asNonEmptyStringArray(value)
	if !ok {
		return nil, failure(ErrTrustChainInvalid, "naming_constraints.%s must be a string array", name)
	}
	return values, nil
}

// entityIdentifierHost returns the lowercased host name of an Entity
// Identifier URL.
func entityIdentifierHost(entityID string) (string, error) {
	parsed, err := url.Parse(entityID)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", failure(ErrTrustChainInvalid, "entity identifier is not a URL")
	}
	return strings.ToLower(parsed.Hostname()), nil
}

// hostInNameSubtree reports whether host is inside subtree: a subtree starting
// with "." matches every host that ends with it and is longer than it, and any
// other subtree matches only the identical host (RFC 5280 Section 4.2.1.10, as
// Section 6.2.2 adopts it).
func hostInNameSubtree(host, subtree string) bool {
	subtree = strings.ToLower(subtree)
	if strings.HasPrefix(subtree, ".") {
		return strings.HasSuffix(host, subtree) && len(host) > len(subtree)
	}
	return host == subtree
}
