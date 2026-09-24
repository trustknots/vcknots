package wallet

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/attestation"
	commonx509 "github.com/trustknots/vcknots/wallet/common/x509"
	oid4vp "github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/profile"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// codedErrorValues is every error this library returns from a public API that
// names its own condition. The test below asserts each one satisfies
// CodedError, that its code is lower_snake_case ASCII, and that no two
// conditions share a code — the three properties an integrator's mapping,
// which may live in another language, depends on.
func codedErrorValues() map[string]error {
	return map[string]error{
		"ErrCredentialAcceptancePolicyRequired":              ErrCredentialAcceptancePolicyRequired,
		"ErrUnknownCredentialConfiguration":                  ErrUnknownCredentialConfiguration,
		"acceptance.ErrHolderBindingConfirmationUnsupported": acceptance.ErrHolderBindingConfirmationUnsupported,
		"acceptance.ErrCredentialParse":                      acceptance.ErrCredentialParse,
		"acceptance.ErrCredentialTypInvalid":                 acceptance.ErrCredentialTypInvalid,
		"acceptance.ErrCredentialAlgUnsupported":             acceptance.ErrCredentialAlgUnsupported,
		"acceptance.ErrHolderBindingMissing":                 acceptance.ErrHolderBindingMissing,
		"acceptance.ErrHolderBindingMismatch":                acceptance.ErrHolderBindingMismatch,
		"acceptance.ErrIssuerKeyUnresolved":                  acceptance.ErrIssuerKeyUnresolved,
		"acceptance.ErrIssuerSignatureInvalid":               acceptance.ErrIssuerSignatureInvalid,
		"acceptance.ErrIssuerDNSBindingFailed":               acceptance.ErrIssuerDNSBindingFailed,
		"acceptance.ErrCredentialExpired":                    acceptance.ErrCredentialExpired,
		"acceptance.ErrCredentialNotYetValid":                acceptance.ErrCredentialNotYetValid,
		"acceptance.ErrDisclosureIntegrity":                  acceptance.ErrDisclosureIntegrity,
		"acceptance.ErrSDAlgUnsupported":                     acceptance.ErrSDAlgUnsupported,
		"acceptance.ErrHAIPX5CRequired":                      acceptance.ErrHAIPX5CRequired,
		"acceptance.ErrHAIPTrustAnchorInX5C":                 acceptance.ErrHAIPTrustAnchorInX5C,
		"ErrKeyAttestationRequired":                          ErrKeyAttestationRequired,
		"ErrKeyAttestationNonceRejected":                     ErrKeyAttestationNonceRejected,
		"ErrIssuanceStateMismatch":                           ErrIssuanceStateMismatch,
		"ErrIssuanceVersionMismatch":                         ErrIssuanceVersionMismatch,
		"ErrDPoPKeyRequired":                                 ErrDPoPKeyRequired,
		"ErrProofAlgorithmNotSupported":                      ErrProofAlgorithmNotSupported,
		"ErrNonceEndpointRequired":                           ErrNonceEndpointRequired,
		"ErrPreAuthorizedGrantMissing":                       ErrPreAuthorizedGrantMissing,
		"ErrTransactionCodeRequired":                         ErrTransactionCodeRequired,
		"ErrTokenTypeUnsupported":                            ErrTokenTypeUnsupported,
		"ErrDPoPKeyMismatch":                                 ErrDPoPKeyMismatch,
		"ErrCredentialResponsePlaintext":                     ErrCredentialResponsePlaintext,
		"ErrCredentialResponseDecrypt":                       ErrCredentialResponseDecrypt,
		"ErrCredentialResponseShape":                         ErrCredentialResponseShape,
		"ErrAuthorizationRedirectInvalid":                    ErrAuthorizationRedirectInvalid,
		"ErrAuthorizationRedirectURIMismatch":                ErrAuthorizationRedirectURIMismatch,
		"ErrAuthorizationStateMismatch":                      ErrAuthorizationStateMismatch,
		"ErrAuthorizationIssMismatch":                        ErrAuthorizationIssMismatch,
		"ErrAuthorizationIssMissing":                         ErrAuthorizationIssMissing,
		"ErrAuthorizationCodeMissing":                        ErrAuthorizationCodeMissing,
		"attestation.ErrClientAttestationInvalid":            attestation.ErrClientAttestationInvalid,
		"attestation.ErrKeyAttestationInvalid":               attestation.ErrKeyAttestationInvalid,

		"oid4vp.ErrRequestObjectTypInvalid":       oid4vp.ErrRequestObjectTypInvalid,
		"oid4vp.ErrRequestObjectSignatureInvalid": oid4vp.ErrRequestObjectSignatureInvalid,
		"oid4vp.ErrRequestObjectAudienceMismatch": oid4vp.ErrRequestObjectAudienceMismatch,
		"oid4vp.ErrRequestObjectExpired":          oid4vp.ErrRequestObjectExpired,
		"oid4vp.ErrRequestObjectClientIDMismatch": oid4vp.ErrRequestObjectClientIDMismatch,
		"oid4vp.ErrX509HashMismatch":              oid4vp.ErrX509HashMismatch,
		"oid4vp.ErrHAIPRequestURIRequired":        oid4vp.ErrHAIPRequestURIRequired,
		"oid4vp.ErrResponseURIInvalid":            oid4vp.ErrResponseURIInvalid,
		"oid4vp.ErrErrorDescriptionInvalid":       oid4vp.ErrErrorDescriptionInvalid,
		"oid4vp.ErrDCQLSelectionUnsatisfied":      oid4vp.ErrDCQLSelectionUnsatisfied,

		"oid4vci.ErrDPoPRequired":                    receiverOid4vci.ErrDPoPRequired,
		"oid4vci.ErrHTTPRedirectNotAllowed":          receiverOid4vci.ErrHTTPRedirectNotAllowed,
		"oid4vci.ErrIssuerIdentifierMismatch":        receiverOid4vci.ErrIssuerIdentifierMismatch,
		"oid4vci.ErrIssuerMetadataSignatureInvalid":  receiverOid4vci.ErrIssuerMetadataSignatureInvalid,
		"oid4vci.ErrIssuerMetadataSubjectMismatch":   receiverOid4vci.ErrIssuerMetadataSubjectMismatch,
		"oid4vci.ErrIssuerMetadataLeafDNSMismatch":   receiverOid4vci.ErrIssuerMetadataLeafDNSMismatch,
		"oid4vci.ErrIssuerMetadataExpired":           receiverOid4vci.ErrIssuerMetadataExpired,
		"oid4vci.ErrIssuerMetadataSignatureRequired": receiverOid4vci.ErrIssuerMetadataSignatureRequired,

		"types.ErrInvalidMetadata":           receiverTypes.ErrInvalidMetadata,
		"types.ErrUnsupportedProtocol":       receiverTypes.ErrUnsupportedProtocol,
		"types.ErrCredentialRequestFailed":   receiverTypes.ErrCredentialRequestFailed,
		"types.ErrInvalidCredentialResponse": receiverTypes.ErrInvalidCredentialResponse,
		"types.ErrAuthorizationFailed":       receiverTypes.ErrAuthorizationFailed,
		"types.ErrTokenRequestFailed":        receiverTypes.ErrTokenRequestFailed,
		"types.ErrInvalidTokenResponse":      receiverTypes.ErrInvalidTokenResponse,
		"types.ErrNonceResponseInvalid":      receiverTypes.ErrNonceResponseInvalid,
		"types.ErrProofGenerationFailed":     receiverTypes.ErrProofGenerationFailed,
		"types.ErrUseDPoPNonce":              receiverTypes.ErrUseDPoPNonce,
		"types.ErrInvalidProofType":          receiverTypes.ErrInvalidProofType,
		"types.ErrNetworkFailed":             receiverTypes.ErrNetworkFailed,
		"types.ErrTimeoutExpired":            receiverTypes.ErrTimeoutExpired,
		"types.ErrPluginNotFound":            receiverTypes.ErrPluginNotFound,
		"types.ErrNilPlugin":                 receiverTypes.ErrNilPlugin,

		"x509.ErrX5CInvalid":                   commonx509.ErrX5CInvalid,
		"ErrAuthorizationDetailsMissing":       ErrAuthorizationDetailsMissing,
		"ErrProfileMismatch":                   ErrProfileMismatch,
		"ErrProfilePluginUnsupported":          ErrProfilePluginUnsupported,
		"ErrProfileForbidsDraft":               ErrProfileForbidsDraft,
		"profile.ErrUnknownProfile":            profile.ErrUnknownProfile,
		"oid4vp.ErrPreRegisteredClientUnknown": oid4vp.ErrPreRegisteredClientUnknown,

		"*AuthorizationResponseError":       &AuthorizationResponseError{Code: "access_denied"},
		"*oid4vp.AuthorizationRequestError": &oid4vp.AuthorizationRequestError{Code: oid4vp.InvalidRequestError, Err: acceptance.ErrCredentialParse},
		"*oid4vp.VerifierResponseError":     &oid4vp.VerifierResponseError{StatusCode: 400},
		"*types.CredentialEndpointError":    &receiverTypes.CredentialEndpointError{StatusCode: 400, Code: "invalid_proof"},
		"*oid4vci.EndpointError":            &receiverOid4vci.EndpointError{Stage: receiverOid4vci.StageToken},
		"*x509.SigningChainError":           &commonx509.SigningChainError{Kind: "path", Err: acceptance.ErrCredentialParse},
		"*x509.CRLCheckError":               &commonx509.CRLCheckError{Kind: commonx509.CRLErrorRevoked},
	}
}

var codePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func TestCodedErrorsExposeUniqueStableCodes(t *testing.T) {
	seen := map[string]string{}
	for name, err := range codedErrorValues() {
		code, ok := ErrorCode(err)
		if !ok {
			t.Errorf("%s does not satisfy CodedError", name)
			continue
		}
		if !codePattern.MatchString(code) {
			t.Errorf("%s code %q is not lower_snake_case ASCII", name, code)
		}
		if previous, duplicate := seen[code]; duplicate {
			t.Errorf("%s and %s share the code %q", previous, name, code)
		}
		seen[code] = name
	}
}

// TestCodedErrorsSurviveWrapping asserts the two properties a caller's mapping
// rests on: a wrapped condition is still found, and an error that classifies
// what it wraps answers for it.
func TestCodedErrorsSurviveWrapping(t *testing.T) {
	wrapped := &receiverTypes.ReceiverError{Op: "receive", Err: acceptance.ErrCredentialExpired}
	if code, _ := ErrorCode(wrapped); code != "credential_expired" {
		t.Errorf("ErrorCode(wrapped) = %q, want credential_expired", code)
	}
	revoked := &commonx509.SigningChainError{
		Kind: "revocation",
		Err:  &commonx509.CRLCheckError{Kind: commonx509.CRLErrorRevoked},
	}
	if code, _ := ErrorCode(revoked); code != "x509_chain_revoked" {
		t.Errorf("ErrorCode(revoked chain) = %q, want x509_chain_revoked", code)
	}
	budget := &commonx509.SigningChainError{
		Kind: "revocation",
		Err:  &commonx509.CRLCheckError{Kind: commonx509.CRLErrorBudget},
	}
	if code, _ := ErrorCode(budget); code != "crl_budget_exhausted" {
		t.Errorf("ErrorCode(budget chain) = %q, want crl_budget_exhausted", code)
	}
	if _, ok := ErrorCode(errUncoded); ok {
		t.Error("an error this library did not classify must report no code")
	}
}

// TestEveryExportedSentinelIsCoded guards the contract against a new sentinel
// being added with errors.New, which would return an error a caller cannot
// classify. It reads the package sources rather than a list, so it fails on the
// commit that introduces the gap.
func TestEveryExportedSentinelIsCoded(t *testing.T) {
	root, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	fileSet := token.NewFileSet()
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "examples" || entry.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(fileSet, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			declaration, ok := node.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for index, name := range declaration.Names {
				if !strings.HasPrefix(name.Name, "Err") || !ast.IsExported(name.Name) {
					continue
				}
				if index >= len(declaration.Values) {
					continue
				}
				call, isCall := declaration.Values[index].(*ast.CallExpr)
				if !isCall {
					continue
				}
				selector, isSelector := call.Fun.(*ast.SelectorExpr)
				if !isSelector {
					continue
				}
				packageName, isIdent := selector.X.(*ast.Ident)
				if !isIdent {
					continue
				}
				if packageName.Name == "errors" && selector.Sel.Name == "New" {
					t.Errorf("%s declares %s with errors.New; use common.NewCodedError so it carries a code",
						mustRelative(root, path), name.Name)
				}
				if packageName.Name == "fmt" && selector.Sel.Name == "Errorf" {
					t.Errorf("%s declares %s with fmt.Errorf; use common.WrapCoded so it carries a code",
						mustRelative(root, path), name.Name)
				}
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk module: %v", walkErr)
	}
}

func mustRelative(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return relative
}

// errUncoded stands for a failure this library has not classified, such as a
// transport error it passes through unchanged.
var errUncoded = &uncodedError{}

type uncodedError struct{}

func (e *uncodedError) Error() string { return "uncoded" }

// TestCodedErrorCodesAreUniqueAcrossTheLibrary reads every code literal the
// library declares, so a new error cannot silently reuse a code another
// condition already means. Uniqueness is what lets an integrator keep one
// mapping for the whole library rather than one per package.
func TestCodedErrorCodesAreUniqueAcrossTheLibrary(t *testing.T) {
	root, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	declared := map[string]string{}
	fileSet := token.NewFileSet()
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "examples" || entry.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// The declaration site of the helpers forwards its own parameters.
		if mustRelative(root, path) == filepath.Join("common", "coded_error.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(fileSet, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			name := calledFunctionName(call.Fun)
			if name != "NewCodedError" && name != "WrapCoded" {
				return true
			}
			literal, isLiteral := call.Args[0].(*ast.BasicLit)
			if !isLiteral || literal.Kind != token.STRING {
				t.Errorf("%s passes a non-literal code to %s", mustRelative(root, path), name)
				return true
			}
			code := strings.Trim(literal.Value, `"`)
			if !codePattern.MatchString(code) {
				t.Errorf("%s declares code %q, which is not lower_snake_case ASCII", mustRelative(root, path), code)
			}
			if previous, duplicate := declared[code]; duplicate {
				t.Errorf("code %q is declared in both %s and %s", code, previous, mustRelative(root, path))
			}
			declared[code] = mustRelative(root, path)
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk module: %v", walkErr)
	}
	if len(declared) == 0 {
		t.Fatal("no coded errors were found; the scan is not reading the library")
	}
}

func calledFunctionName(expression ast.Expr) string {
	switch target := expression.(type) {
	case *ast.Ident:
		return target.Name
	case *ast.SelectorExpr:
		return target.Sel.Name
	}
	return ""
}

// TestErrorCodesReportsTheMostSpecificConditionFirst pins the order a consumer
// with its own table of conditions depends on.
func TestErrorCodesReportsTheMostSpecificConditionFirst(t *testing.T) {
	endpoint := &receiverOid4vci.EndpointError{
		Stage: receiverOid4vci.StageIssuerMetadata,
		Err:   receiverOid4vci.ErrIssuerIdentifierMismatch,
	}
	codes := ErrorCodes(endpoint)
	want := []string{"issuer_metadata_identity_mismatch", "issuer_metadata_fetch_failed"}
	if len(codes) != len(want) || codes[0] != want[0] || codes[1] != want[1] {
		t.Fatalf("ErrorCodes(endpoint) = %v, want %v", codes, want)
	}
	if code, _ := ErrorCode(endpoint); code != "issuer_metadata_fetch_failed" {
		t.Errorf("ErrorCode(endpoint) = %q, want the outermost issuer_metadata_fetch_failed", code)
	}
	if got := ErrorCodes(errUncoded); len(got) != 0 {
		t.Errorf("ErrorCodes(uncoded) = %v, want none", got)
	}
}
