import { z } from 'zod'
import { Dcql } from './dcql.type'
import { DeepPartialUnknown } from './type.utils'

const credentialQueryOptionsSchema = z.object({
  kind: z.literal('dcql'),
  query: Dcql.schema,
})

export type CredentialQueryOptions = z.infer<typeof credentialQueryOptionsSchema>
export const CredentialQueryOptions = (value?: DeepPartialUnknown<CredentialQueryOptions>) =>
  credentialQueryOptionsSchema.parse(value)
CredentialQueryOptions.schema = credentialQueryOptionsSchema

export type CredentialQuery = Dcql
export type CredentialQueryType = 'dcql'
