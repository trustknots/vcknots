package wallet

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// errorGateCases runs known failure paths of every exported function and
// method of this package that returns an error. A case name starts with the
// function or method it covers ("Wallet.BeginIssuance", "Draft13Issuance.NotifyIssuer",
// "NewWalletWithConfig"), which TestErrorGateCoversEveryExportedMethod checks.
func errorGateCases() map[string]func(t *testing.T) error {
	ctx := context.Background()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	token := &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "Bearer"}

	return map[string]func(t *testing.T) error{
		"Wallet.ResolveCredentialOffer: no offer": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.ResolveCredentialOffer(ctx, "openid-credential-offer://")
			return err
		},
		"Wallet.ResolveCredentialOffer: missing offer document": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.ResolveCredentialOffer(ctx, "openid-credential-offer://?credential_offer_uri="+f.server.URL+"/missing")
			return err
		},
		"Wallet.BeginIssuance: canceled": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.BeginIssuance(canceled, f.issuanceRequest())
			return err
		},
		"Wallet.BeginIssuance: unreachable issuer": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			f.server.Close()
			_, err := f.wallet.BeginIssuance(ctx, f.issuanceRequest())
			return err
		},
		"Wallet.BeginIssuance: foreign authorization server issuer": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) { f.asIssuerOverride = "https://other.example" })
			_, err := f.wallet.BeginIssuance(ctx, f.issuanceRequest())
			return err
		},
		"Wallet.AuthorizeIssuance: nil state": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.AuthorizeIssuance(ctx, nil, "")
			return err
		},
		"Wallet.AuthorizeIssuance: foreign redirect": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			authorization, err := f.wallet.BeginIssuance(ctx, f.issuanceRequest())
			require.NoError(t, err)
			_, err = f.wallet.AuthorizeIssuance(ctx, authorization, "https://attacker.example/cb?code=x")
			return err
		},
		"Wallet.AuthorizeIssuance: token endpoint refuses": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
				f.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
					mockserver.JSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
				}
			})
			_, err := f.authorize(f.issuanceRequest())
			return err
		},
		"Wallet.AuthorizePreAuthorizedIssuance: no grant": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.AuthorizePreAuthorizedIssuance(ctx, PreAuthorizedIssuanceRequest{CredentialOffer: f.offer()})
			return err
		},
		"Wallet.RequestCredential: no holder keys": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			grant, err := f.authorize(f.issuanceRequest())
			require.NoError(t, err)
			_, err = f.wallet.RequestCredential(ctx, grant, CredentialRequest{})
			return err
		},
		"Wallet.RequestCredential: credential endpoint refuses": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
				f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
					mockserver.JSONResponse(w, http.StatusBadRequest, map[string]any{"error": "credential_request_denied"})
				}
			})
			_, err := f.receive(f.issuanceRequest())
			return err
		},
		"Wallet.RequestCredential: Draft 13 grant": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.RequestCredential(ctx, &IssuanceGrant{Version: IssuanceVersionDraft13}, f.credentialRequest())
			return err
		},
		"Wallet.RequestDeferredCredential: incomplete state": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.RequestDeferredCredential(ctx, &DeferredIssuance{Version: IssuanceVersionFinal})
			return err
		},
		"Wallet.RequestDeferredCredential: no deferred endpoint": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.RequestDeferredCredential(ctx, &DeferredIssuance{
				Version: IssuanceVersionFinal, CredentialIssuer: f.server.URL, CredentialConfigurationID: "pid",
				TransactionID: "tx-1", AccessToken: token,
			})
			return err
		},
		"Wallet.NotifyIssuer: invalid event": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			return f.wallet.NotifyIssuer(ctx, &IssuanceNotification{
				Version: IssuanceVersionFinal, CredentialIssuer: f.server.URL, NotificationID: "n-1", AccessToken: token,
			}, NotificationEvent("credential_lost"), "")
		},
		"Wallet.NotifyIssuer: no notification endpoint": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			return f.wallet.NotifyIssuer(ctx, &IssuanceNotification{
				Version: IssuanceVersionFinal, CredentialIssuer: f.server.URL, NotificationID: "n-1", AccessToken: token,
			}, NotificationCredentialAccepted, "")
		},
		"Draft13Issuance.AuthorizePreAuthorizedIssuance: HAIP": func(t *testing.T) error {
			f := newHAIPIssuanceFixture(t)
			_, err := f.wallet.Draft13().AuthorizePreAuthorizedIssuance(ctx, PreAuthorizedIssuanceRequest{CredentialOffer: f.offer()})
			return err
		},
		"Draft13Issuance.BeginIssuance: no offer": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.Draft13().BeginIssuance(ctx, IssuanceRequest{})
			return err
		},
		"Wallet.ReceiveCredential: no offer": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.ReceiveCredential(ReceiveCredentialRequest{Type: receiverTypes.Oid4vci})
			return err
		},
		"Wallet.AuthorizePreAuthorizedIssuance: canceled": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.AuthorizePreAuthorizedIssuance(canceled, PreAuthorizedIssuanceRequest{CredentialOffer: f.offer()})
			return err
		},
		"Wallet.RequestDeferredCredential: nil state": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.RequestDeferredCredential(ctx, nil)
			return err
		},
		"Draft13Issuance.AuthorizeIssuance: nil state": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.Draft13().AuthorizeIssuance(ctx, nil, "")
			return err
		},
		"Draft13Issuance.AuthorizeIssuance: 1.0 state": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.Draft13().AuthorizeIssuance(ctx, &IssuanceAuthorization{Version: IssuanceVersionFinal}, "")
			return err
		},
		"Draft13Issuance.AuthorizePreAuthorizedIssuance: no offer": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.Draft13().AuthorizePreAuthorizedIssuance(ctx, PreAuthorizedIssuanceRequest{})
			return err
		},
		"Draft13Issuance.RequestCredential: 1.0 grant": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.Draft13().RequestCredential(ctx, &IssuanceGrant{Version: IssuanceVersionFinal}, f.credentialRequest())
			return err
		},
		"Draft13Issuance.RequestCredential: nil grant": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.Draft13().RequestCredential(ctx, nil, f.credentialRequest())
			return err
		},
		"Draft13Issuance.RequestDeferredCredential: 1.0 state": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.Draft13().RequestDeferredCredential(ctx, &DeferredIssuance{Version: IssuanceVersionFinal})
			return err
		},
		"Draft13Issuance.NotifyIssuer: 1.0 state": func(t *testing.T) error {
			return newFinalIssuanceFixture(t).wallet.Draft13().NotifyIssuer(ctx, &IssuanceNotification{Version: IssuanceVersionFinal}, NotificationCredentialAccepted, "")
		},
		"Draft13Issuance.NotifyIssuer: nil state": func(t *testing.T) error {
			return newFinalIssuanceFixture(t).wallet.Draft13().NotifyIssuer(ctx, nil, NotificationCredentialAccepted, "")
		},
		"Wallet.ReceiveCredential: receiver refused by SetReceiver": func(t *testing.T) error {
			w := newFinalIssuanceFixture(t).wallet
			w.SetReceiver(nil)
			_, err := w.ReceiveCredential(ReceiveCredentialRequest{Type: receiverTypes.Oid4vci})
			return err
		},
		"Wallet.FetchCredentialIssuerMetadata: unreachable issuer": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			f.server.Close()
			endpoint, err := url.Parse(f.server.URL)
			require.NoError(t, err)
			_, err = f.wallet.FetchCredentialIssuerMetadata(endpoint, receiverTypes.Oid4vci)
			return err
		},
		"Wallet.FetchCredentialIssuerMetadata: nil endpoint": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.FetchCredentialIssuerMetadata(nil, receiverTypes.Oid4vci)
			return err
		},
		"Wallet.FetchCredentialIssuerMetadata: relative endpoint": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.FetchCredentialIssuerMetadata(&url.URL{Path: "issuer"}, receiverTypes.Oid4vci)
			return err
		},
		"Wallet.VerifyCredentialForAcceptance: no policy": func(t *testing.T) error {
			w, err := NewWalletWithConfig(Config{Storeless: true})
			require.NoError(t, err)
			_, _, err = w.VerifyCredentialForAcceptance(ctx, []byte("a.b.c"), credential.SDJwtVC, nil)
			return err
		},
		"Wallet.VerifyCredentialForAcceptance: not a credential": func(t *testing.T) error {
			_, _, err := newFinalIssuanceFixture(t).wallet.VerifyCredentialForAcceptance(ctx, []byte("not a credential"), credential.SDJwtVC, nil)
			return err
		},
		"Wallet.GenerateDID: not a DID type": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.GenerateDID(DIDCreateOptions{TypeID: "key"})
			return err
		},
		"Wallet.GenerateDID: unknown DID method": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.GenerateDID(DIDCreateOptions{TypeID: "did:unknown"})
			return err
		},
		"Wallet.GetCredentialEntries: storeless": func(t *testing.T) error {
			_, _, err := storelessWallet(t).GetCredentialEntries(GetCredentialEntriesRequest{})
			return err
		},
		"Wallet.GetCredentialEntry: storeless": func(t *testing.T) error {
			_, err := storelessWallet(t).GetCredentialEntry("any")
			return err
		},
		"NewWalletWithConfig: unknown profile": func(t *testing.T) error {
			_, err := NewWalletWithConfig(Config{Profile: profile.Profile("unknown")})
			return err
		},
		"NewWalletWithConfig: store on a storeless wallet": func(t *testing.T) error {
			_, err := NewWalletWithConfig(Config{Storeless: true, CredStore: fixtureCredStore(t)})
			return err
		},
		"ParseCredentialOfferURL: not an offer": func(t *testing.T) error {
			_, err := ParseCredentialOfferURL("https://issuer.example/?credential_offer=%7B")
			return err
		},
		"Wallet.ParsePresentationRequest: not a request": func(t *testing.T) error {
			_, err := newSDJWTPresentationFixture(t).wallet.ParsePresentationRequest(ctx, "not a request")
			return err
		},
		"Wallet.ParsePresentationRequest: no dcql_query": func(t *testing.T) error {
			_, err := newSDJWTPresentationFixture(t).wallet.ParsePresentationRequest(ctx, "openid4vp://?client_id=redirect_uri:https://verifier.example/response&response_uri=https://verifier.example/response&response_type=vp_token&response_mode=direct_post&nonce=n")
			return err
		},
		"Wallet.ParsePresentationRequestObject: not a JWS": func(t *testing.T) error {
			_, err := newSDJWTPresentationFixture(t).wallet.ParsePresentationRequestObject(ctx, "not a JWS", presenterTypes.RequestObjectSource{ClientID: "x509_san_dns:verifier.example"})
			return err
		},
		"Wallet.ParseDCAPIRequest: empty invocation": func(t *testing.T) error {
			_, err := newSDJWTPresentationFixture(t).wallet.ParseDCAPIRequest(ctx, presenterTypes.DCAPIInvocation{})
			return err
		},
		"Wallet.SelectCredentials: nil handle": func(t *testing.T) error {
			_, err := newSDJWTPresentationFixture(t).wallet.SelectCredentials(ctx, nil)
			return err
		},
		"Wallet.SelectCredentials: nothing stored": func(t *testing.T) error {
			f := newSDJWTPresentationFixture(t)
			_, err := f.wallet.SelectCredentials(ctx, parsedPresentationRequest(t, f, presentationURI(f.baseURL, identityDCQLQuery)))
			return err
		},
		"Wallet.SelectCredentials: canceled": func(t *testing.T) error {
			f := newSDJWTPresentationFixture(t)
			_, err := f.wallet.SelectCredentials(canceled, parsedPresentationRequest(t, f, presentationURI(f.baseURL, identityDCQLQuery)))
			return err
		},
		"Wallet.SubmitPresentation: nil handle": func(t *testing.T) error {
			_, err := newSDJWTPresentationFixture(t).wallet.SubmitPresentation(ctx, nil, Presentation{})
			return err
		},
		"Wallet.SubmitPresentation: unknown credential": func(t *testing.T) error {
			f := newSDJWTPresentationFixture(t)
			request := parsedPresentationRequest(t, f, presentationURI(f.baseURL, identityDCQLQuery))
			_, err := f.wallet.SubmitPresentation(ctx, request, Presentation{Key: f.key, Credentials: []CredentialSelection{{CredentialID: "missing", QueryIDs: []string{"pid"}}}})
			return err
		},
		"Wallet.DeclinePresentation: nil handle": func(t *testing.T) error {
			_, err := newSDJWTPresentationFixture(t).wallet.DeclinePresentation(ctx, nil, "access_denied", "")
			return err
		},
		"Wallet.DeclinePresentation: unreachable verifier": func(t *testing.T) error {
			f := newSDJWTPresentationFixture(t)
			closed := httptest.NewTLSServer(http.NotFoundHandler())
			closed.Close()
			request := parsedPresentationRequest(t, f, presentationURI(closed.URL, identityDCQLQuery))
			_, err := f.wallet.DeclinePresentation(ctx, request, "access_denied", "")
			return err
		},
		"Wallet.PresentCredential: not a request": func(t *testing.T) error {
			f := newSDJWTPresentationFixture(t)
			_, err := f.wallet.PresentCredential("not a request", f.key, nil)
			return err
		},
		"Wallet.PresentCredentialWithOptions: nothing stored": func(t *testing.T) error {
			f := newSDJWTPresentationFixture(t)
			_, err := f.wallet.PresentCredentialWithOptions(presentationURI(f.baseURL, identityDCQLQuery), f.key, nil)
			return err
		},
		"Draft24Presentation.ParsePresentationRequest: HAIP": func(t *testing.T) error {
			_, err := newHAIPIssuanceFixture(t).wallet.Draft24().ParsePresentationRequest(ctx, draft24PresentationURI("https://verifier.example", "direct_post", ""))
			return err
		},
		"Draft24Presentation.ParsePresentationRequest: not a request": func(t *testing.T) error {
			_, err := newSDJWTPresentationFixture(t).wallet.Draft24().ParsePresentationRequest(ctx, "not a request")
			return err
		},
		"Draft24Presentation.ParsePresentationRequestObject: HAIP": func(t *testing.T) error {
			_, err := newHAIPIssuanceFixture(t).wallet.Draft24().ParsePresentationRequestObject(ctx, "a.b.c", presenterTypes.RequestObjectSource{})
			return err
		},
		"Draft24Presentation.ParsePresentationRequestObject: not a JWS": func(t *testing.T) error {
			_, err := newSDJWTPresentationFixture(t).wallet.Draft24().ParsePresentationRequestObject(ctx, "not a JWS", presenterTypes.RequestObjectSource{ClientID: "x509_san_dns:verifier.example"})
			return err
		},
	}
}

// TestExportedMethodErrorsAreCoded is the gate for CodedError promise 2: every
// known failure path of an exported method yields a code, and never
// unclassified, which marks a failure the library did not name.
func TestExportedMethodErrorsAreCoded(t *testing.T) {
	for name, run := range errorGateCases() {
		t.Run(name, func(t *testing.T) {
			err := run(t)
			require.Error(t, err)
			code, ok := ErrorCode(err)
			require.True(t, ok, "error has no code: %v", err)
			require.NotEqual(t, "unclassified", code, "error: %v", err)
		})
	}
}

// errorGateExempt lists exported functions that return an error but have no
// failure path of their own to drive.
var errorGateExempt = map[string]string{
	"NewWallet": "NewWalletWithConfig with the zero Config",
}

// TestErrorGateCoversEveryExportedMethod requires a case in errorGateCases for
// every exported function and method of this package that returns an error,
// so a new method cannot skip the gate.
func TestErrorGateCoversEveryExportedMethod(t *testing.T) {
	cases := errorGateCases()
	fset := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() || !returnsError(fn) {
				continue
			}
			name := fn.Name.Name
			if fn.Recv != nil {
				receiver := receiverTypeName(fn.Recv.List[0].Type)
				if !ast.IsExported(receiver) || slices.Contains([]string{"Error", "Unwrap", "ErrorCode", "Is"}, name) {
					continue
				}
				name = receiver + "." + name
			}
			if _, exempt := errorGateExempt[name]; exempt {
				continue
			}
			covered := false
			for caseName := range cases {
				covered = covered || strings.HasPrefix(caseName, name+": ")
			}
			require.True(t, covered, "%s returns an error but has no case in errorGateCases", name)
		}
	}
}

func returnsError(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, result := range fn.Type.Results.List {
		if ident, ok := result.Type.(*ast.Ident); ok && ident.Name == "error" {
			return true
		}
	}
	return false
}

func receiverTypeName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// storelessWallet is a wallet built with Config.Storeless.
func storelessWallet(t *testing.T) *Wallet {
	t.Helper()
	w, err := NewWalletWithConfig(Config{Storeless: true})
	require.NoError(t, err)
	return w
}
