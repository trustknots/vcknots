import { CredentialConfigurationId } from './credential-issuer.types'

export type CredentialIssuanceContext = {
  jti: string
  credentialConfigurationIds: CredentialConfigurationId[]
}
