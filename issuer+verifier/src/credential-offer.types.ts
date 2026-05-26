import { z } from 'zod'
import { CredentialConfigurationId, CredentialIssuer } from './credential-issuer.types'

const txCodeSchema = z
  .object({
    input_mode: z.enum(['numeric', 'text']).optional(),
    length: z.number().int().positive().optional(),
    description: z.string().optional(),
  })
  .optional()

const preAuthorizedCodeGrantSchema = z
  .object({
    'pre-authorized_code': z.string(),
    tx_code: txCodeSchema,
  })
  .optional()

const authorizationCodeGrantSchema = z
  .object({
    issuer_state: z.string().optional(),
  })
  .optional()

const grantsSchema = z
  .object({
    authorization_code: authorizationCodeGrantSchema,
    'urn:ietf:params:oauth:grant-type:pre-authorized_code': preAuthorizedCodeGrantSchema,
  })
  .optional()

export const credentialOfferSchema = z.object({
  credential_issuer: CredentialIssuer.schema,
  grants: grantsSchema,
  credential_configuration_ids: z.array(CredentialConfigurationId.schema),
})

export type CredentialOffer = z.infer<typeof credentialOfferSchema>
export type Grants = z.infer<typeof grantsSchema>
export type PreAuthorizedCodeGrant = z.infer<typeof preAuthorizedCodeGrantSchema>
export type AuthorizationCodeGrant = z.infer<typeof authorizationCodeGrantSchema>
export type TxCode = z.infer<typeof txCodeSchema>

export const CredentialOffer = (value?: {
  credential_issuer?: string
  grants?: unknown // TODO: Define the appropriate type
  credential_configuration_ids: string[]
}) => credentialOfferSchema.parse(value)
CredentialOffer.schema = credentialOfferSchema

export const TxCode = (value?: {
  input_mode?: string
  length?: string | number
  description?: string
}) => txCodeSchema.parse(value)
TxCode.schema = txCodeSchema
