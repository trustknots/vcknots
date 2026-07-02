import { Dcql } from '../dcql.type'
import { err } from '../errors'
import { CredentialQueryProvider } from './provider.types'
import { DcqlQuery } from 'dcql'

const META_KEYS_BY_FORMAT: Record<string, string[]> = {
  mso_mdoc: ['doctype_value'],
  'dc+sd-jwt': ['vct_values'],
  ldp_vc: ['type_values'],
  jwt_vc_json: ['type_values'],
}

const validateMetaKeysByFormat = (credentials: unknown[]) => {
  for (const cred of credentials) {
    if (typeof cred !== 'object' || cred === null) continue
    const { format, meta } = cred as Record<string, unknown>
    if (typeof meta !== 'object' || meta === null) continue

    const allowed = META_KEYS_BY_FORMAT[format as string]
    if (!allowed) continue

    const invalid = Object.keys(meta).filter((k) => !allowed.includes(k))
    if (invalid.length > 0) {
      throw err('INVALID_REQUEST', {
        message: `credential format '${format}' meta must only contain [${allowed.map((k) => `'${k}'`).join(', ')}], found invalid keys: [${invalid.map((k) => `'${k}'`).join(', ')}]`,
      })
    }
  }
}

export const dcql = (): CredentialQueryProvider => {
  return {
    kind: 'credential-query-provider',
    name: 'default-dcql-provider',
    single: true,

    async generate(query) {
      try {
        const parsed = DcqlQuery.parse(query.dcql_query as unknown as DcqlQuery.Input)
        DcqlQuery.validate(parsed)
        const credentials = query.dcql_query?.credentials
        if (credentials) {
          validateMetaKeysByFormat(credentials)
        }
        return Dcql({ dcql_query: parsed })
      } catch (e) {
        throw err('INVALID_REQUEST', {
          message: `invalid dcql query: ${e}`,
        })
      }
    },
  }
}
