import { z } from 'zod'
import { CredentialIssuer } from './credential-issuer.types'

/** OID4VCI JWT proof: aud must match credentialIssuer; iss rules depend on usePreAuth (draft 13 §7.2.1.1). */
export const credentialProofJwtVerifyContextSchema = z.discriminatedUnion('usePreAuth', [
  z.object({
    usePreAuth: z.literal(true),
    credentialIssuer: CredentialIssuer.schema,
  }),
  z.object({
    usePreAuth: z.literal(false),
    credentialIssuer: CredentialIssuer.schema,
    clientId: z.string().optional(),
  }),
])

export type CredentialProofJwtVerifyContext = z.infer<typeof credentialProofJwtVerifyContextSchema>

export const CredentialProofJwtVerifyContext = (
  value: z.input<typeof credentialProofJwtVerifyContextSchema>
) => credentialProofJwtVerifyContextSchema.parse(value)
CredentialProofJwtVerifyContext.schema = credentialProofJwtVerifyContextSchema
