import { z } from 'zod'
import { CredentialConfigurationId } from './credential-issuer.types'

const allowedCredentialConfigurationStoreEntrySchema = z.object({
  credential_configuration_ids: z.array(CredentialConfigurationId.schema),
  expires_at: z.number(),
})
export type AllowedCredentialConfigurationStoreEntry = z.infer<
  typeof allowedCredentialConfigurationStoreEntrySchema
>
export const AllowedCredentialConfigurationStoreEntry = (value?: Partial<AllowedCredentialConfigurationStoreEntry>) =>
  allowedCredentialConfigurationStoreEntrySchema.parse(value)
