import { z } from 'zod'
import { CredentialConfigurationId } from './credential-issuer.types'

const credentialIssuanceStoreEntrySchema = z.object({
  credential_configuration_ids: z.array(CredentialConfigurationId.schema),
  expires_at: z.number(),
})
export type CredentialIssuanceStoreEntry = z.infer<typeof credentialIssuanceStoreEntrySchema>
export const CredentialIssuanceStoreEntry = (value?: Partial<CredentialIssuanceStoreEntry>) =>
  credentialIssuanceStoreEntrySchema.parse(value)
