import { CredentialOffer, TxCode } from '../credential-offer.types'
import { CredentialOfferProvider } from './provider.types'

export const credentialOffer = (): CredentialOfferProvider => {
  return {
    kind: 'credential-offer-provider',
    name: 'default-credential-offer-provider',
    single: true,

    async create(issuer, configurations, options): Promise<CredentialOffer> {
      const txCode =
        options.usePreAuth &&
        options.txCode &&
        TxCode({
          input_mode: options.txCode.inputMode,
          length: options.txCode.length,
          description: options.txCode.description,
        })

      const grants = options.usePreAuth
        ? {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              'pre-authorized_code': options.code,
              ...(txCode && { tx_code: txCode }),
              ...(options.authorizationServer && {
                authorization_server: options.authorizationServer,
              }),
            },
          }
        : {
            authorization_code: {
              issuer_state: String(options.state),
              ...(options.authorizationServer && {
                authorization_server: options.authorizationServer,
              }),
            },
          }

      return {
        credential_issuer: issuer.credential_issuer,
        credential_configuration_ids: configurations,
        grants,
      }
    },
  }
}
