import { err } from '../errors/vcknots.error'
import { PresentationExchange } from '../presentation-exchange.types'
import { CredentialQueryProvider } from './provider.types'

export const presentationExchange = (): CredentialQueryProvider => {
  return {
    kind: 'credential-query-provider',
    name: 'default-presentation-exchange-provider',
    single: false,

    async generate(options) {
      if (options.kind !== 'presentation-exchange') {
        throw err('illegal_argument', { message: `"${options.kind}" is not supported.` })
      }
      return PresentationExchange(options.query)
    },
    canHandle(query) {
      return query === 'presentation-exchange'
    },
  }
}
