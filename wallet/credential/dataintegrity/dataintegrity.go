// Package dataintegrity secures JSON-LD documents with W3C Verifiable
// Credential Data Integrity 1.0 proofs of the eddsa-rdfc-2022 cryptosuite
// (W3C VC Data Integrity EdDSA Cryptosuites v1.0, Section 3.2).
//
// A proof is computed over the RDF Dataset Canonicalization (RDFC-1.0) of the
// document, which means expanding the JSON-LD against its contexts. Fetching a
// context over the network while signing or verifying would let whoever serves
// it change what the signature covers, so this package never does: every
// context a document names has to be supplied up front as a PinnedContexts
// entry, and a document naming any other URL is refused with
// ErrContextNotPinned (VC Data Integrity 1.0 Section 2.4.1 and the security
// considerations of Section 5.1 recommend exactly this).
//
// RDFC-1.0 canonicalization can take time exponential in the number of blank
// nodes that share a first-degree hash (RDFC-1.0 Section 4.4 and its security
// considerations on dataset poisoning), and the underlying processor offers no
// cancellation. Canonicalize therefore refuses, before canonicalizing, a
// dataset with more than 1024 blank nodes or with more than 6 blank nodes whose
// first-degree hash is not unique, with ErrCanonicalizationTooComplex.
package dataintegrity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/piprate/json-gold/ld"

	"github.com/trustknots/vcknots/wallet/common"
)

const (
	// ProofType is the proof `type` of VC Data Integrity 1.0 Section 2.1.
	ProofType = "DataIntegrityProof"
	// CryptosuiteEddsaRdfc2022 names the Ed25519 cryptosuite over RDFC-1.0
	// (VC Data Integrity EdDSA Cryptosuites v1.0 Section 3.2).
	CryptosuiteEddsaRdfc2022 = "eddsa-rdfc-2022"
	// ProofPurposeAssertionMethod is the purpose an issuer signs a credential
	// with.
	ProofPurposeAssertionMethod = "assertionMethod"
	// ProofPurposeAuthentication is the purpose a holder signs a presentation
	// with (VC Data Model 2.0 Section 4.13 and Data Integrity Section 2.2).
	ProofPurposeAuthentication = "authentication"

	// ed25519SignatureSize is the size of an Ed25519 signature (RFC 8032).
	ed25519SignatureSize = ed25519.SignatureSize

	// maxBlankNodes bounds the blank nodes of a dataset Canonicalize accepts.
	maxBlankNodes = 1024
	// maxAmbiguousBlankNodes bounds the blank nodes whose first-degree hash is
	// shared with another blank node, the only ones RDFC-1.0 runs the
	// exponential Hash N-Degree Quads algorithm on. Six such nodes in one
	// clique canonicalize in tens of milliseconds; each further node costs
	// roughly ten times more.
	maxAmbiguousBlankNodes = 6
)

var (
	// ErrContextNotPinned reports a document naming a JSON-LD context URL the
	// caller did not pin. No network fetch is ever attempted.
	ErrContextNotPinned = common.NewCodedError("data_integrity_context_not_pinned", "JSON-LD context is not pinned")
	// ErrInvalidDocument reports a document that cannot carry or be checked
	// against a Data Integrity proof.
	ErrInvalidDocument = common.NewCodedError("data_integrity_invalid_document", "invalid Data Integrity document")
	// ErrCanonicalizationFailed reports a JSON-LD expansion or RDFC-1.0
	// canonicalization failure, including a term that does not expand to an
	// IRI and would otherwise be dropped from the signed dataset silently.
	ErrCanonicalizationFailed = common.NewCodedError("data_integrity_canonicalization_failed", "RDFC-1.0 canonicalization failed")
	// ErrSigningFailed reports a signer error or a signature of the wrong size.
	ErrSigningFailed = common.NewCodedError("data_integrity_signing_failed", "Data Integrity proof signing failed")
	// ErrCanonicalizationTooComplex reports a dataset whose RDFC-1.0
	// canonicalization this package refuses to attempt because its blank nodes
	// exceed the bounds described in the package documentation.
	ErrCanonicalizationTooComplex = common.NewCodedError("data_integrity_canonicalization_too_complex", "RDFC-1.0 canonicalization exceeds the blank node bounds")
	// ErrProofInvalid reports a proof that does not verify.
	ErrProofInvalid = common.NewCodedError("data_integrity_proof_invalid", "Data Integrity proof is invalid")
)

// PinnedContexts maps a JSON-LD context URL to the document it resolves to,
// exactly as it would be served (an object carrying "@context"). It is the
// entire set of remote contexts a document may use.
type PinnedContexts map[string]any

// ProofOptions are the proof configuration members of VC Data Integrity 1.0
// Section 2.1 this package sets. VerificationMethod, ProofPurpose and Created
// are required; Challenge and Domain are included only when non-empty.
type ProofOptions struct {
	VerificationMethod string
	ProofPurpose       string
	Created            time.Time
	// Challenge binds the proof to one exchange; a holder presenting to an
	// OpenID4VP Verifier sets it to the request nonce.
	Challenge string
	// Domain binds the proof to its audience; a holder presenting to an
	// OpenID4VP Verifier sets it to the Verifier's client_id.
	Domain string
}

// Signer signs the eddsa-rdfc-2022 hash data and returns the 64-byte Ed25519
// signature over it.
type Signer func(hashData []byte) ([]byte, error)

// SignEddsaRdfc2022 returns a copy of the unsecured document with an
// eddsa-rdfc-2022 DataIntegrityProof attached (VC Data Integrity EdDSA
// Cryptosuites v1.0 Sections 3.2.1 to 3.2.6). The document must not already
// carry a proof, and every context it names must be pinned.
func SignEddsaRdfc2022(document map[string]any, options ProofOptions, contexts PinnedContexts, sign Signer) (map[string]any, error) {
	if document == nil {
		return nil, fmt.Errorf("%w: document is required", ErrInvalidDocument)
	}
	if _, secured := document["proof"]; secured {
		return nil, fmt.Errorf("%w: the document already carries a proof", ErrInvalidDocument)
	}
	if _, ok := document["@context"]; !ok {
		return nil, fmt.Errorf("%w: @context is required", ErrInvalidDocument)
	}
	if strings.TrimSpace(options.VerificationMethod) == "" {
		return nil, fmt.Errorf("%w: verificationMethod is required", ErrInvalidDocument)
	}
	if options.ProofPurpose == "" {
		return nil, fmt.Errorf("%w: proofPurpose is required", ErrInvalidDocument)
	}
	if options.Created.IsZero() {
		return nil, fmt.Errorf("%w: created is required", ErrInvalidDocument)
	}
	if sign == nil {
		return nil, fmt.Errorf("%w: signer is required", ErrSigningFailed)
	}

	proofConfig := map[string]any{
		"type":               ProofType,
		"cryptosuite":        CryptosuiteEddsaRdfc2022,
		"created":            formatDateTime(options.Created),
		"proofPurpose":       options.ProofPurpose,
		"verificationMethod": options.VerificationMethod,
	}
	if options.Challenge != "" {
		proofConfig["challenge"] = options.Challenge
	}
	if options.Domain != "" {
		proofConfig["domain"] = options.Domain
	}

	hashData, err := HashData(document, proofConfig, contexts)
	if err != nil {
		return nil, err
	}
	signature, err := sign(hashData)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigningFailed, err)
	}
	if len(signature) != ed25519SignatureSize {
		return nil, fmt.Errorf("%w: an Ed25519 signature is %d bytes, the signer returned %d", ErrSigningFailed, ed25519SignatureSize, len(signature))
	}

	proof := make(map[string]any, len(proofConfig)+1)
	for name, value := range proofConfig {
		proof[name] = value
	}
	// Section 3.2.6: proofValue is the base58-btc multibase encoding.
	proof["proofValue"] = "z" + base58.Encode(signature)

	secured := make(map[string]any, len(document)+1)
	for name, value := range document {
		secured[name] = value
	}
	secured["proof"] = proof
	return secured, nil
}

// VerifyOptions are a verifier's expectations of a proof (VC Data Integrity
// 1.0 Section 4.4, Verify Proof). Empty fields impose nothing.
type VerifyOptions struct {
	// ProofPurpose, when non-empty, must equal the proof's proofPurpose.
	ProofPurpose string
	// VerificationMethod, when non-empty, must equal the proof's
	// verificationMethod. It also selects the proof to verify from a proof
	// set (Section 2.1.1).
	VerificationMethod string
	// Challenge, when non-empty, must equal the proof's challenge.
	Challenge string
	// Domain, when non-empty, must equal the proof's domain or one of its
	// values.
	Domain string
	// Now, when non-zero, is the verification time: a proof created after Now
	// plus ClockSkew, or whose expires is not after Now minus ClockSkew, is
	// refused.
	Now time.Time
	// ClockSkew is the tolerance applied with Now.
	ClockSkew time.Duration
}

// VerifyEddsaRdfc2022 is VerifyEddsaRdfc2022WithOptions with no expectations
// beyond a well-formed proof that verifies under publicKey.
func VerifyEddsaRdfc2022(document map[string]any, contexts PinnedContexts, publicKey ed25519.PublicKey) error {
	return VerifyEddsaRdfc2022WithOptions(document, contexts, publicKey, VerifyOptions{})
}

// VerifyEddsaRdfc2022WithOptions verifies an eddsa-rdfc-2022 proof of a
// secured document under publicKey (VC Data Integrity EdDSA Cryptosuites v1.0
// Section 3.2.2) and checks it against options.
//
// The document's `proof` is one proof object or a proof set (an array, VC
// Data Integrity 1.0 Section 2.1.1). The proof verified is the
// eddsa-rdfc-2022 DataIntegrityProof of the set, selected by
// options.VerificationMethod when the set holds several. Proof chains
// (previousProof) are not supported and are refused. `created` and `expires`,
// when present, must be dateTimeStamp values. Resolving which key the proof's
// verificationMethod names, and whether it may be used for the proof purpose,
// is the caller's decision.
func VerifyEddsaRdfc2022WithOptions(document map[string]any, contexts PinnedContexts, publicKey ed25519.PublicKey, options VerifyOptions) error {
	proof, err := selectProof(document["proof"], options.VerificationMethod)
	if err != nil {
		return err
	}
	if err := checkProof(proof, options); err != nil {
		return err
	}
	proofValue, ok := proof["proofValue"].(string)
	if !ok || !strings.HasPrefix(proofValue, "z") {
		return fmt.Errorf("%w: proofValue must be a base58-btc multibase string", ErrProofInvalid)
	}
	signature := base58.Decode(proofValue[1:])
	if len(signature) != ed25519SignatureSize {
		return fmt.Errorf("%w: proofValue does not decode to an Ed25519 signature", ErrProofInvalid)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: an Ed25519 public key is required", ErrProofInvalid)
	}

	unsecured := make(map[string]any, len(document))
	for name, value := range document {
		if name != "proof" {
			unsecured[name] = value
		}
	}
	proofConfig := make(map[string]any, len(proof))
	for name, value := range proof {
		if name != "proofValue" {
			proofConfig[name] = value
		}
	}
	hashData, err := HashData(unsecured, proofConfig, contexts)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, hashData, signature) {
		return fmt.Errorf("%w: signature verification failed", ErrProofInvalid)
	}
	return nil
}

// selectProof returns the eddsa-rdfc-2022 proof of a `proof` member that is a
// proof object or a proof set, narrowed to verificationMethod when non-empty.
func selectProof(member any, verificationMethod string) (map[string]any, error) {
	var proofs []any
	switch typed := member.(type) {
	case map[string]any:
		proofs = []any{typed}
	case []any:
		proofs = typed
	}
	if len(proofs) == 0 {
		return nil, fmt.Errorf("%w: the document must carry a proof object or a non-empty proof set", ErrProofInvalid)
	}
	var selected []map[string]any
	for _, entry := range proofs {
		proof, ok := entry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: every proof must be an object", ErrProofInvalid)
		}
		if proof["type"] != ProofType || proof["cryptosuite"] != CryptosuiteEddsaRdfc2022 {
			continue
		}
		if verificationMethod != "" && proof["verificationMethod"] != verificationMethod {
			continue
		}
		selected = append(selected, proof)
	}
	switch len(selected) {
	case 0:
		return nil, fmt.Errorf("%w: no %s DataIntegrityProof matches", ErrProofInvalid, CryptosuiteEddsaRdfc2022)
	case 1:
		return selected[0], nil
	default:
		return nil, fmt.Errorf("%w: several %s proofs match; name the verificationMethod", ErrProofInvalid, CryptosuiteEddsaRdfc2022)
	}
}

// checkProof applies the proof member rules of VC Data Integrity 1.0 Section
// 2.1 and the verifier's options to proof.
func checkProof(proof map[string]any, options VerifyOptions) error {
	if _, chained := proof["previousProof"]; chained {
		return fmt.Errorf("%w: proof chains are not supported", ErrProofInvalid)
	}
	purpose, _ := proof["proofPurpose"].(string)
	if purpose == "" {
		return fmt.Errorf("%w: proofPurpose is required", ErrProofInvalid)
	}
	if options.ProofPurpose != "" && purpose != options.ProofPurpose {
		return fmt.Errorf("%w: proofPurpose %q is not %q", ErrProofInvalid, purpose, options.ProofPurpose)
	}
	if method, _ := proof["verificationMethod"].(string); method == "" {
		return fmt.Errorf("%w: verificationMethod is required", ErrProofInvalid)
	}
	if options.Challenge != "" && proof["challenge"] != options.Challenge {
		return fmt.Errorf("%w: challenge does not match", ErrProofInvalid)
	}
	if options.Domain != "" && !proofDomainIncludes(proof["domain"], options.Domain) {
		return fmt.Errorf("%w: domain does not match", ErrProofInvalid)
	}
	created, err := proofTime(proof, "created")
	if err != nil {
		return err
	}
	expires, err := proofTime(proof, "expires")
	if err != nil {
		return err
	}
	if options.Now.IsZero() {
		return nil
	}
	if !created.IsZero() && created.After(options.Now.Add(options.ClockSkew)) {
		return fmt.Errorf("%w: proof was created in the future", ErrProofInvalid)
	}
	if !expires.IsZero() && !expires.After(options.Now.Add(-options.ClockSkew)) {
		return fmt.Errorf("%w: proof has expired", ErrProofInvalid)
	}
	return nil
}

// proofDomainIncludes reports whether a proof's domain, a string or an array
// of strings, includes want.
func proofDomainIncludes(domain any, want string) bool {
	switch typed := domain.(type) {
	case string:
		return typed == want
	case []any:
		return slices.Contains(typed, any(want))
	default:
		return false
	}
}

// proofTime reads an optional dateTimeStamp member of a proof (XML Schema
// dateTimeStamp, which requires a time zone), or the zero time when absent.
func proofTime(proof map[string]any, name string) (time.Time, error) {
	raw, present := proof[name]
	if !present {
		return time.Time{}, nil
	}
	text, ok := raw.(string)
	if !ok {
		return time.Time{}, fmt.Errorf("%w: %s must be a dateTimeStamp", ErrProofInvalid, name)
	}
	instant, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s must be a dateTimeStamp", ErrProofInvalid, name)
	}
	return instant, nil
}

// HashData is the eddsa-rdfc-2022 hash data of Section 3.2.4: the SHA-256 of
// the canonical proof configuration followed by the SHA-256 of the canonical
// unsecured document. The proof configuration inherits the document's
// @context (Section 3.2.5) unless it names one of its own, in which case both
// apply, the document's first.
func HashData(unsecured map[string]any, proofConfig map[string]any, contexts PinnedContexts) ([]byte, error) {
	documentContext, ok := unsecured["@context"]
	if !ok {
		return nil, fmt.Errorf("%w: @context is required", ErrInvalidDocument)
	}
	configDocument := make(map[string]any, len(proofConfig)+1)
	for name, value := range proofConfig {
		if name != "@context" {
			configDocument[name] = value
		}
	}
	if ownContext, present := proofConfig["@context"]; present {
		configDocument["@context"] = []any{documentContext, ownContext}
	} else {
		configDocument["@context"] = documentContext
	}

	canonicalConfig, err := Canonicalize(configDocument, contexts)
	if err != nil {
		return nil, err
	}
	canonicalDocument, err := Canonicalize(unsecured, contexts)
	if err != nil {
		return nil, err
	}
	configHash := sha256.Sum256([]byte(canonicalConfig))
	documentHash := sha256.Sum256([]byte(canonicalDocument))
	return append(configHash[:], documentHash[:]...), nil
}

// Canonicalize returns the RDFC-1.0 canonical N-Quads of a JSON-LD document
// expanded against the pinned contexts only. A term that does not expand to
// an absolute IRI fails the canonicalization instead of being dropped, so a
// claim the signer cannot vouch for is never silently left unsigned. A dataset
// beyond the blank node bounds of the package documentation fails with
// ErrCanonicalizationTooComplex before any canonicalization work.
func Canonicalize(document map[string]any, contexts PinnedContexts) (string, error) {
	loader, err := newPinnedLoader(contexts)
	if err != nil {
		return "", err
	}
	// JSON-LD numbers are read as float64 by json-gold; round-tripping the
	// document through encoding/json keeps the caller's Go values (json.Number,
	// integers, nested structs) from reaching the processor in a shape it does
	// not expect.
	normalizedInput, err := jsonRoundTrip(document)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidDocument, err)
	}

	options := ld.NewJsonLdOptions("")
	options.ProcessingMode = ld.JsonLd_1_1
	options.DocumentLoader = loader
	options.SafeMode = true

	// JsonLdProcessor.Normalize builds its own toRDF options and drops
	// SafeMode (json-gold v0.8.0), so the dataset is produced here with the
	// caller's options and only then canonicalized.
	dataset, err := ld.NewJsonLdProcessor().ToRDF(normalizedInput, options)
	if err != nil {
		if loader.refused != nil {
			return "", loader.refused
		}
		return "", fmt.Errorf("%w: %w", ErrCanonicalizationFailed, err)
	}
	rdfDataset, ok := dataset.(*ld.RDFDataset)
	if !ok {
		return "", fmt.Errorf("%w: unexpected RDF dataset %T", ErrCanonicalizationFailed, dataset)
	}
	if err := checkBlankNodeBounds(rdfDataset); err != nil {
		return "", err
	}
	options.Algorithm = ld.AlgorithmURDNA2015 // RDFC-1.0 with SHA-256
	options.Format = "application/n-quads"
	normalized, err := ld.NewJsonLdApi().Normalize(rdfDataset, options)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCanonicalizationFailed, err)
	}
	nquads, ok := normalized.(string)
	if !ok {
		return "", fmt.Errorf("%w: unexpected canonicalization output %T", ErrCanonicalizationFailed, normalized)
	}
	return nquads, nil
}

// checkBlankNodeBounds refuses a dataset whose canonicalization could take
// exponential time. It groups the blank nodes by their first-degree quads
// (RDFC-1.0 Section 4.6: every quad naming the node, with the node written as
// one label and every other blank node as another) and counts the nodes whose
// group has more than one member.
func checkBlankNodeBounds(dataset *ld.RDFDataset) error {
	quadsOf := map[string][]string{}
	for graphName, quads := range dataset.Graphs {
		for _, quad := range quads {
			graph := quad.Graph
			if graph == nil && strings.HasPrefix(graphName, "_:") {
				graph = ld.NewBlankNode(graphName)
			}
			nodes := []ld.Node{quad.Subject, quad.Predicate, quad.Object, graph}
			for _, node := range nodes {
				if node == nil || !ld.IsBlankNode(node) {
					continue
				}
				label := node.GetValue()
				if len(quadsOf) >= maxBlankNodes {
					if _, known := quadsOf[label]; !known {
						return fmt.Errorf("%w: more than %d blank nodes", ErrCanonicalizationTooComplex, maxBlankNodes)
					}
				}
				quadsOf[label] = append(quadsOf[label], firstDegreeQuad(nodes, label))
			}
		}
	}
	groups := map[string]int{}
	for _, quads := range quadsOf {
		slices.Sort(quads)
		groups[strings.Join(quads, "\n")]++
	}
	ambiguous := 0
	for _, size := range groups {
		if size > 1 {
			ambiguous += size
		}
	}
	if ambiguous > maxAmbiguousBlankNodes {
		return fmt.Errorf("%w: %d blank nodes share a first-degree hash, the limit is %d", ErrCanonicalizationTooComplex, ambiguous, maxAmbiguousBlankNodes)
	}
	return nil
}

// firstDegreeQuad serializes one quad for the blank node label: label becomes
// "_:a" and every other blank node "_:z" (RDFC-1.0 Section 4.6 step 3). The
// encoding need only be injective, not N-Quads.
func firstDegreeQuad(nodes []ld.Node, label string) string {
	parts := make([]string, len(nodes))
	for index, node := range nodes {
		switch {
		case node == nil:
			parts[index] = "-"
		case ld.IsBlankNode(node) && node.GetValue() == label:
			parts[index] = "_:a"
		case ld.IsBlankNode(node):
			parts[index] = "_:z"
		default:
			if literal, ok := node.(*ld.Literal); ok {
				parts[index] = fmt.Sprintf("L%q^%q@%q", literal.Value, literal.Datatype, literal.Language)
			} else {
				parts[index] = fmt.Sprintf("I%q", node.GetValue())
			}
		}
	}
	return strings.Join(parts, " ")
}

// pinnedLoader is the only document loader the canonicalization uses. It
// answers from the pinned set and records the first URL it had to refuse, so
// the caller sees ErrContextNotPinned rather than the processor's generic
// loading failure.
type pinnedLoader struct {
	contexts map[string]any
	refused  error
}

func newPinnedLoader(contexts PinnedContexts) (*pinnedLoader, error) {
	loader := &pinnedLoader{contexts: make(map[string]any, len(contexts))}
	for url, document := range contexts {
		object, ok := document.(map[string]any)
		if !ok {
			normalized, err := jsonRoundTrip(document)
			if err != nil {
				return nil, fmt.Errorf("%w: pinned context %s: %w", ErrInvalidDocument, url, err)
			}
			object, ok = normalized.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%w: pinned context %s must be a JSON object", ErrInvalidDocument, url)
			}
		}
		if _, ok := object["@context"]; !ok {
			return nil, fmt.Errorf("%w: pinned context %s must carry @context", ErrInvalidDocument, url)
		}
		loader.contexts[url] = object
	}
	return loader, nil
}

func (l *pinnedLoader) LoadDocument(url string) (*ld.RemoteDocument, error) {
	document, ok := l.contexts[url]
	if !ok {
		if l.refused == nil {
			l.refused = fmt.Errorf("%w: %s", ErrContextNotPinned, url)
		}
		return nil, l.refused
	}
	return &ld.RemoteDocument{DocumentURL: url, Document: document}, nil
}

func jsonRoundTrip(value any) (any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

// formatDateTime renders created as an XML Schema dateTime in UTC with
// millisecond precision, the form VC Data Integrity 1.0 Section 2.1 requires.
func formatDateTime(instant time.Time) string {
	return instant.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}
