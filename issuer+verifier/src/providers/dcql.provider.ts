import { Dcql } from '../dcql.type'
import { err } from '../errors'
import { CredentialQueryProvider } from './provider.types'

export const dcql = (): CredentialQueryProvider => {
  return {
    kind: 'credential-query-provider',
    name: 'default-dcql-provider',
    single: false,

    async generate(options) {
      if (options.kind !== 'dcql') {
        throw err('illegal_argument', {
          message: `${options.kind} is not supported.`,
        })
      }
      return Dcql(options.query)
    },
    canHandle(query: 'presentation-exchange' | 'dcql') {
      return query === 'dcql'
    },
  }
}
