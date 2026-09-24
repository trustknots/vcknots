package wallet

import (
	"context"

	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

// RedirectHandler is called when the verifier returns a redirect URI.
type RedirectHandler func(string) error

// PresentCredentialOptions configures presentation serialization and redirect handling.
type PresentCredentialOptions struct {
	SerializeOptions serializerTypes.SerializePresentationOptions
	OnRedirect       RedirectHandler
}

// PresentCredential orchestrates the credential presentation flow.
func (w *Wallet) PresentCredential(uriString string, key IKeyEntry, options serializerTypes.SerializePresentationOptions) (string, error) {
	return w.PresentCredentialWithOptions(uriString, key, &PresentCredentialOptions{SerializeOptions: options})
}

// PresentCredentialWithOptions orchestrates presentation and invokes redirect handler if provided.
//
// It is ParsePresentationRequest, SelectCredentials and SubmitPresentation
// with the library's own credential choice.
func (w *Wallet) PresentCredentialWithOptions(uriString string, key IKeyEntry, options *PresentCredentialOptions) (string, error) {
	var serializeOptions serializerTypes.SerializePresentationOptions
	var onRedirect RedirectHandler
	if options != nil {
		serializeOptions = options.SerializeOptions
		onRedirect = options.OnRedirect
	}

	ctx := context.Background()
	request, err := w.ParsePresentationRequest(ctx, uriString)
	if err != nil {
		return "", err
	}
	selections, err := w.SelectCredentials(ctx, request)
	if err != nil {
		return "", err
	}
	result, err := w.SubmitPresentation(ctx, request, Presentation{
		Key:              key,
		Credentials:      selections,
		SerializeOptions: serializeOptions,
	})
	if err != nil {
		return "", err
	}

	redirectURI := result.RedirectURI
	if redirectURI != "" && onRedirect != nil {
		if err := onRedirect(redirectURI); err != nil {
			return redirectURI, err
		}
	}
	return redirectURI, nil
}
