// Package experimental holds every setting of the wallet library that departs
// from the OpenID4VC specifications and the specifications they build on.
// They exist to test a peer — a local issuer or verifier without TLS, a
// verifier whose certificate chain cannot be validated, or how an issuer or
// verifier handles a malformed message — and are not for production use.
//
// Design. The rest of the library conforms to the specifications and has no
// switch that turns a MUST off. A departure is reachable only through a type
// this package defines, carried by a field named Experimental:
//
//   - wallet.Config.Experimental (Options) for the wallet and the plugins it
//     builds;
//   - oid4vci.Oid4vciReceiver.Experimental (Transport) for an injected
//     OpenID4VCI receiver;
//   - oid4vp.Oid4vpPresenter.Experimental (Presenter) for an injected
//     OpenID4VP presenter;
//   - issuerkeys.Resolver.Experimental (Transport) for the issuer key
//     resolution of the credential acceptor and of the Status List checker;
//   - statuslist.Checker.Experimental (Transport) for the Status List Token
//     retrieval.
//   - acceptance.IssuerX509TrustOptions.Experimental (Transport) for the
//     binding of an http iss to an x5c leaf.
//
// Code that relaxes a rule therefore imports this package, which makes the
// departure visible in review and searchable. The rules are:
//
//   - The zero value of every type here is the conforming behavior.
//   - Nothing here is read from the environment or from global state; a
//     setting takes effect only where a caller sets it.
//   - A profile that forbids a departure refuses it rather than ignoring it:
//     profile.Options.ForbidExperimental (HAIP) refuses Transport wherever
//     it is carried, any non-zero Presenter on every presenter entry point,
//     and Hooks. Hooks, which rewrite draft protocol messages, are also
//     refused unless a draft profile is enabled.
//   - A new departure is added as a field of one of these types (or a new
//     type in this package), never as a field of a stable configuration type.
package experimental

import (
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

// Options are the departures a wallet.Config can carry. Not
// specification-conforming; for testing only.
type Options struct {
	// Transport relaxes transport security for the protocol plugins the
	// wallet builds. A wallet refuses it when an injected Receiver or
	// Presenter would not receive it; set Oid4vciReceiver.Experimental on an
	// injected receiver instead.
	Transport Transport
	// Hooks rewrite draft protocol messages the library built.
	Hooks Hooks
}

// Transport relaxes transport security. Not specification-conforming; for
// testing only.
type Transport struct {
	// AllowHTTP accepts plain http endpoints and identifiers, for a local test
	// issuer or verifier. OpenID4VCI 1.0 Section 12.2.1 requires the https
	// scheme for a Credential Issuer Identifier and Section 12.2.2 TLS for
	// metadata; OpenID4VP 1.0 and HAIP 1.0 require TLS throughout. A profile
	// with ForbidExperimental (HAIP) refuses it. A client assertion is
	// still sent over plain http only to a loopback host.
	AllowHTTP bool
}

// Presenter relaxes the OpenID4VP presenter
// (oid4vp.Oid4vpPresenter.Experimental). Each field makes the presenter
// accept requests a conforming Wallet refuses. Not specification-conforming;
// for testing only.
type Presenter struct {
	// Transport.AllowHTTP accepts http for request_uri and for the Response
	// URI or Redirect URI of a local test verifier. OpenID4VP 1.0 Section 5.10
	// and Draft 24 Section 5.11 require https for a request_uri POST, and HAIP
	// 1.0 Section 5 requires TLS; a profile with ForbidExperimental
	// refuses it.
	Transport Transport
	// InsecureSkipX509Verify authenticates a Draft 24 x509_san_dns Request
	// Object by its binding and signature only, without verifying the
	// certificate chain; the request is admitted without a
	// RequestObjectVerification. Draft 24 Section 5.10.4 has the Wallet
	// "validate the signature and the trust chain of the X.509 certificate".
	// The OpenID4VP 1.0 entry points refuse every signed Request Object while
	// it is set, and a profile with ForbidExperimental refuses it.
	InsecureSkipX509Verify bool
	// AcceptClientMetadataJWKsWithoutKeyID accepts a client_metadata.jwks
	// member without a kid, or with a kid another member repeats, on the
	// OpenID4VP 1.0 entry points. OpenID4VP 1.0 Section 5.1 states "Each JWK
	// in the set MUST have a kid (Key ID) parameter that uniquely identifies
	// the key within the context of the request". Draft 24 has no such rule,
	// and its entry points never check kid.
	AcceptClientMetadataJWKsWithoutKeyID bool
}

// Hooks rewrite messages after the library built them, so a tester can see
// how an issuer or verifier handles a malformed one. A nil hook leaves its
// message unchanged. They rewrite draft protocol messages only, so a wallet
// refuses them (wallet.ErrProfileForbidsDraft) unless Config.Profiles enables
// a draft profile, and a profile with ForbidExperimental (HAIP) refuses them
// (wallet.ErrInvalidArgument). Not specification-conforming; for testing
// only.
type Hooks struct {
	// KeyProof rewrites Draft 13 key proofs.
	KeyProof ProofTransform
	// PresentationExchangeResponse rewrites Draft 24 Presentation Exchange
	// responses.
	PresentationExchangeResponse Draft24ResponseTransform
}

// Set reports whether any hook is set.
func (h Hooks) Set() bool {
	return h.KeyProof.Content != nil || h.KeyProof.Serialized != nil || h.PresentationExchangeResponse != nil
}

// ProofJWTContent is the header and claims of a key proof before it is
// signed. Both maps are copies a transform may change. Header never carries
// "alg": the algorithm belongs to the signing key.
type ProofJWTContent struct {
	Header map[string]any
	Claims map[string]any
}

// ProofTransform rewrites a Draft 13 key proof, for testing how an issuer
// handles a malformed one. Content runs before signing, so the result is
// still correctly signed; Serialized runs on the compact JWS. A nil member is
// not called, so the zero value leaves the proof unchanged. An error aborts
// the issuance with wallet.ErrDraft13ProofTransformFailed.
type ProofTransform struct {
	Content    func(ProofJWTContent) (ProofJWTContent, error)
	Serialized func(string) (string, error)
}

// Draft24ResponseTransform rewrites a Presentation Exchange response after
// the library built and signed it and before it is sent, so a tester can see
// how a Verifier handles a malformed one. A rewrite can break the proof. An
// error stops the presentation and is reported wrapped in
// wallet.ErrDraft24ResponseTransformFailed.
type Draft24ResponseTransform func(vpToken []byte, submission presenterTypes.PresentationSubmission) ([]byte, presenterTypes.PresentationSubmission, error)
