import {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
} from '../authorization-server.types'
import type { ClientIdentifier } from '../client-id-prefix.types'
import { AuthzOAuthClient } from '../authz-oauth-client.types'
import { AuthzOAuthPolicy } from '../authz-oauth-policy.types'
import { ClientId } from '../client-id.types'
import { Nonce } from '../nonce.types'
import {
  CredentialConfigurationSupported,
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialIssuerMetadata,
} from '../credential-issuer.types'
import { CredentialOffer } from '../credential-offer.types'
import { CredentialQuery } from '../credential-query.type'

import { CredentialFormats } from '../credential-request.types'
import { JwtVcJson, ProofJwt, ProofJwtHeader, VerifiableCredential } from '../credential.types'
import { Dcql } from '../dcql.type'
import { DidDocument } from '../did.types'
import { EncryptionKeyPair, EncryptionPublicJwk } from '../encryption-key.types'
import { JwtContent, JwtPayload } from '../jwt.types'
import { PreAuthorizedCode } from '../pre-authorized-code.types'
import { VpTokenPayload } from '../presentation.types'
import { RequestObjectId } from '../request-object-id.types'
import { RequestObject } from '../request-object.types'
import { Certificate, SignatureKeyPair, SignatureKeyEntry } from '../signature-key.types'
import { Transaction, TransactionId, TransactionRecord } from '../transaction-id.types'
import { DeepPartialUnknown } from '../type.utils'
import { VerifierMetadata } from '../verifier-metadata.types'
import type { CredentialProofJwtVerifyContext } from '../credential-proof-jwt.types'
import type { DPoPProofVerifyContext, VerifiedDpopProof } from '../dpop-proof.types'
import { DiVpProof } from '../proofs.types'

export type { CredentialProofJwtVerifyContext } from '../credential-proof-jwt.types'
export type { DPoPProofVerifyContext, VerifiedDpopProof } from '../dpop-proof.types'

export type AuthzRequestProviderOptions = {
  kid?: string
  jwk?: Record<string, unknown>
  x5c?: string[]
  x5t?: string
  x5tS256?: string
}

export type IssuerMetadataStoreProvider = {
  kind: 'issuer-metadata-store-provider'
  name: string
  single: true

  fetch(issuer: CredentialIssuer): Promise<CredentialIssuerMetadata | null>
  save(metadata: CredentialIssuerMetadata): Promise<void>
}

export type AuthzServerMetadataStoreProvider = {
  kind: 'authz-server-metadata-store-provider'
  name: string
  single: true

  fetch(issuer: AuthorizationServerIssuer): Promise<AuthorizationServerMetadata | null>
  save(metadata: AuthorizationServerMetadata): Promise<void>
}

export type AuthzOAuthPolicyStoreProvider = {
  kind: 'authz-oauth-policy-store-provider'
  name: string
  single: true

  fetch(issuer: AuthorizationServerIssuer): Promise<AuthzOAuthPolicy | null>
  save(issuer: AuthorizationServerIssuer, policy: AuthzOAuthPolicy): Promise<void>
}

export type AuthzOAuthClientStoreProvider = {
  kind: 'authz-oauth-client-store-provider'
  name: string
  single: true

  fetch(
    issuer: AuthorizationServerIssuer,
    clientId: AuthzOAuthClient['client_id']
  ): Promise<AuthzOAuthClient | null>
  save(issuer: AuthorizationServerIssuer, client: AuthzOAuthClient): Promise<void>
}

export type OAuthClientAssertionJtiStoreProvider = {
  kind: 'oauth-client-assertion-jti-store-provider'
  name: string
  single: true

  saveIfAbsent(
    clientId: AuthzOAuthClient['client_id'],
    jti: string,
    options?: { ttlMs?: number }
  ): Promise<boolean>
}

export type VerifierMetadataStoreProvider = {
  kind: 'verifier-metadata-store-provider'
  name: string
  single: true

  fetch(verifier: ClientId): Promise<VerifierMetadata | null>
  save(id: ClientId, metadata: VerifierMetadata): Promise<void>
}

export type AuthzSignatureKeyStoreProvider = {
  kind: 'authz-signature-key-store-provider'
  name: string
  single: true

  save(authz: AuthorizationServerIssuer, keyAlg: string, pair?: SignatureKeyEntry): Promise<void>
  fetch(authz: AuthorizationServerIssuer, keyAlg: string): Promise<CryptoKey | null>
  sign(
    authz: AuthorizationServerIssuer,
    keyAlg: string,
    jwtPayload: JwtPayload,
    jwtHeader: ProofJwtHeader
  ): Promise<string | null>
}

export type IssuerSignatureKeyStoreProvider = {
  kind: 'issuer-signature-key-store-provider'
  name: string
  single: true

  save(issuer: CredentialIssuer, keyAlg: string, pair?: SignatureKeyEntry): Promise<void>
  fetch(issuer: CredentialIssuer, keyAlg: string): Promise<CryptoKey | null>
  sign(
    issuer: CredentialIssuer,
    keyAlg: string,
    jwtPayload: JwtPayload,
    jwtHeader: ProofJwtHeader
  ): Promise<string | null>
}

export type VerifierEncryptionKeyStoreProvider = {
  kind: 'verifier-encryption-key-store-provider'
  name: string
  single: true

  save(verifier: ClientId, keyAlg: string): Promise<void>
  fetch(verifier: ClientId, keyAlg: string): Promise<EncryptionPublicJwk | null>
}

export type VerifierSignatureKeyStoreProvider = {
  kind: 'verifier-signature-key-store-provider'
  name: string
  single: true

  save(verifier: ClientId, keyAlg: string, pair?: SignatureKeyEntry): Promise<void>
  fetch(verifier: ClientId, keyAlg: string): Promise<CryptoKey | null>
  sign(
    verifierId: ClientId,
    keyAlg: string,
    jwtPayload: JwtPayload,
    jwtHeader: ProofJwtHeader
  ): Promise<string | null>
}

export type VerifierCertificateStoreProvider = {
  kind: 'verifier-certificate-store-provider'
  name: string
  single: true

  save(verifier: ClientId, cert: Certificate): Promise<void>
  fetch(verifier: ClientId): Promise<Certificate>
}

export type RequestObjectStoreProvider = {
  kind: 'request-object-store-provider'
  name: string
  single: true

  fetch(id: RequestObjectId): Promise<RequestObject | null>
  save(id: RequestObjectId, RequestObject: RequestObject): Promise<void>
  delete(id: RequestObjectId): Promise<void>
}

export type RequestObjectIdProvider = {
  kind: 'request-object-id-provider'
  name: string
  single: true

  generate(): Promise<RequestObjectId>
}

export type VerifyCredentialProvider = {
  kind: 'verify-verifiable-credential-provider'
  name: string
  single: true

  verify(vc: string, options?: { allowedAlgs?: string[] }): Promise<boolean>
  canHandle(format: string): boolean
}

export type VerifyVerifiablePresentationVerifyOptions =
  | {
      kind: 'jwt_vp_json'
      /** VP JWT `aud` must equal this or be included if `aud` is an array. */
      expectedAud: ClientIdentifier
      expectedNonce?: string
      allowedAlgs?: string[]
    }
  | {
      kind: 'dc+sd-jwt'
      specifiedDisclosures?: string[]
      isKbJwt?: false
      expectedAud?: ClientIdentifier
      expectedNonce?: string
      expectedTransactionDataHashes?: string[]
      allowedSdJwtAlgs?: string[]
      allowedKbJwtAlgs?: string[]
    }
  | {
      kind: 'dc+sd-jwt'
      specifiedDisclosures?: string[]
      isKbJwt: true
      expectedAud: ClientIdentifier
      expectedNonce?: string
      expectedTransactionDataHashes?: string[]
      allowedSdJwtAlgs?: string[]
      allowedKbJwtAlgs?: string[]
    }
// | {
//     kind: 'dc+sd-jwt'
//     specifiedDisclosures?: string[]
//     isKbJwt?: boolean
//     expectedAud?: ClientIdentifier
//     expectedNonce?: string
//     expectedTransactionDataHashes?: string[]
//   }
export type VerifyVerifiablePresentationProvider = {
  kind: 'verify-verifiable-presentation-provider'
  name: string
  single: false

  verify(vp: string, options?: VerifyVerifiablePresentationVerifyOptions): Promise<VpTokenPayload>
  canHandle(format: string): boolean
}

export type JwtSignatureProvider = {
  kind: 'jwt-signature-provider'
  name: string
  single: true
  verify(jwt: string, publicKey: JsonWebKey): Promise<boolean>
}

export type HolderBindingProvider = {
  kind: 'holder-binding-provider'
  name: string
  single: true

  verify(credentials: VerifiableCredential<JwtVcJson>[], publicKey: JsonWebKey): Promise<boolean>
}

export type IdentifierProvider = {
  kind: 'identifier-provider'
  name: string
  single: true
}

export type PublicKeyResolverProvider = {
  kind: 'public-key-resolver-provider'
  name: string
  single: false
}

export type DidProvider = {
  kind: 'did-provider'
  name: string
  single: false

  resolveDid(kid: string): Promise<DidDocument | null>
  canHandle(method: string): boolean
}

export type CredentialFormatProvider = {
  kind: 'credential-format-provider'
  name: string
  single: true
}

export type CredentialProofProvider = {
  kind: 'credential-proof-provider'
  name: string
  single: false

  verifyProof(
    proof: string | DiVpProof,
    context?: CredentialProofJwtVerifyContext
  ): Promise<ProofJwt | null>
  canHandle(proofType: string): boolean
}

export type CredentialRevocationProvider = {
  kind: 'credential-revocation-provider'
  name: string
  single: true
}

export type DPoPProofProvider = {
  kind: 'dpop-proof-provider'
  name: string
  single: true
  proofJtiTtlMs: number

  verifyProof(proofJwt: string, context: DPoPProofVerifyContext): Promise<VerifiedDpopProof>
}

export type DPoPProofJtiStoreProvider = {
  kind: 'dpop-proof-jti-store-provider'
  name: string
  single: true

  saveIfAbsent(jwkThumbprint: string, jti: string, options?: { ttlMs?: number }): Promise<boolean>
}

export type SignatureGenerationProvider = {
  kind: 'signature-generation-provider'
  name: string
  single: false
}

export type SignatureVerificationProvider = {
  kind: 'signature-verification-provider'
  name: string
  single: false
}

export type PreAuthorizedCodeProvider = {
  kind: 'pre-authorized-code-provider'
  name: string
  single: true

  generate(): Promise<PreAuthorizedCode>
}
export type PreAuthorizedCodeStoreProvider = {
  kind: 'pre-authorized-code-store-provider'
  name: string
  single: true

  save(
    code: PreAuthorizedCode,
    credentialConfigurationIds: CredentialConfigurationId[],
    tx_code?: string | number,
    options?: { ttlSec?: number; tx_code_input_mode?: 'numeric' | 'text' }
  ): Promise<void>
  consume(
    code: PreAuthorizedCode,
    tx_code?: string | number
  ): Promise<CredentialConfigurationId[] | null>
}

export type AllowedCredentialConfigurationStoreProvider = {
  kind: 'allowed-credential-configuration-store-provider'
  name: string
  single: true

  save(
    accessTokenHash: string,
    credential_configuration_ids: CredentialConfigurationId[],
    ttlSec?: number
  ): Promise<void>
  fetch(accessTokenHash: string): Promise<CredentialConfigurationId[] | null>
  delete(accessTokenHash: string): Promise<void>
}

export type AccessTokenProvider = {
  kind: 'access-token-provider'
  name: string
  single: true

  createTokenPayload(
    authz: AuthorizationServerIssuer,
    code: PreAuthorizedCode,
    options?: {
      ttlSec?: number
      cnf?: { jkt: string }
      clientId?: AuthzOAuthClient['client_id']
    }
  ): Promise<JwtPayload>
}

export type AuthzSignatureKeyProvider = {
  kind: 'authz-signature-key-provider'
  name: string
  single: false

  generate(): Promise<SignatureKeyPair>
  canHandle(keyAlg: string): boolean
}

export type IssuerSignatureKeyProvider = {
  kind: 'issuer-signature-key-provider'
  name: string
  single: false

  generate(): Promise<SignatureKeyPair>
  canHandle(keyAlg: string): boolean
}

export type VerifierEncryptionKeyProvider = {
  kind: 'verifier-encryption-key-provider'
  name: string
  single: false

  generate(): Promise<EncryptionKeyPair>
  canHandle(keyAlg: string): boolean
}

export type VerifierSignatureKeyProvider = {
  kind: 'verifier-signature-key-provider'
  name: string
  single: false

  generate(): Promise<SignatureKeyPair>
  canHandle(keyAlg: string): boolean
}

export type TransactionCodeProvider = {
  kind: 'transaction-code-provider'
  name: string
  single: true

  generate(input_mode?: 'numeric' | 'text', length?: number, description?: string): string | number
}

export type CredentialOfferProvider = {
  kind: `credential-offer-provider`
  name: string
  single: true

  create(
    issuer: CredentialIssuerMetadata,
    configurations: CredentialConfigurationId[],
    options:
      | {
          usePreAuth: true
          code: PreAuthorizedCode
          txCode?: {
            inputMode?: 'numeric' | 'text'
            length?: number
            description?: string
          }
          authorizationServer?: string
        }
      | {
          usePreAuth: false
          state: unknown
          authorizationServer?: string
        }
  ): Promise<CredentialOffer>
}

export type NonceProvider = {
  kind: 'nonce-provider'
  name: string
  single: true

  generate(options?: { nonce_expires_in?: number }): Promise<Nonce>
}

export type NonceStoreProvider = {
  kind: 'nonce-store-provider'
  name: string
  single: true

  save(nonce: Nonce): Promise<void>
  validate(nonce: Nonce): Promise<boolean>
  revoke(nonce: Nonce): Promise<boolean>
  consume(nonce: Nonce): Promise<boolean>
}

export type IssueCredentialCreateCredentialOptions = {
  claims?: Record<string, unknown>
  subject?: string
  keyAlg?: string
  proofHeader?: ProofJwtHeader
  nonDisclosableClaims?: string[]
}

export type IssueCredentialProvider = {
  kind: 'issue-credential-provider'
  name: string
  single: false

  createCredential(
    credentialIssuer: CredentialIssuer,
    configuration: CredentialConfigurationSupported,
    options?: IssueCredentialCreateCredentialOptions
  ): Promise<string>
  canHandle(format: CredentialFormats): boolean
}

export type CredentialQueryProvider = {
  kind: 'credential-query-provider'
  name: string
  single: true

  generate(query: DeepPartialUnknown<Dcql>): Promise<CredentialQuery>
}

export type AuthzRequestJARProvider = {
  kind: 'authz-request-jar-provider'
  name: string
  single: false

  generate(
    verifierId: ClientId,
    requestObject: RequestObject,
    alg: string,
    wallet_nonce?: string
  ): Promise<JwtContent>
  canHandle(clientIdPrefix: string): boolean
}

export type CertificateProvider = {
  kind: 'certificate-provider'
  name: string
  single: true

  validate(cert: string | string[]): Promise<boolean>
  getPublicKey(cert: string): string
}

export type TransactionDataProvider = {
  kind: 'transaction-data-provider'
  name: string
  single: true

  generate(type: string, credential_ids: string[], transaction_data_hashes_alg?: string[]): string
}

export type TransactionIdProvider = {
  kind: 'transaction-id-provider'
  name: string
  single: true

  generate(): Promise<TransactionId>
}

export type VerifierTransactionDataStoreProvider = {
  kind: 'verifier-transaction-store-provider'
  name: string
  single: true

  fetch(transactionId: TransactionId): Promise<Transaction | null>
  save(transactionId: TransactionId, record: TransactionRecord): Promise<void>
  delete(transactionId: TransactionId): Promise<void>
}

export type Provider =
  | IssuerMetadataStoreProvider
  | IssuerSignatureKeyStoreProvider
  | IdentifierProvider
  | PublicKeyResolverProvider
  | CredentialFormatProvider
  | CredentialProofProvider
  | DPoPProofProvider
  | DPoPProofJtiStoreProvider
  | CredentialRevocationProvider
  | SignatureGenerationProvider
  | SignatureVerificationProvider
  | PreAuthorizedCodeProvider
  | PreAuthorizedCodeStoreProvider
  | AllowedCredentialConfigurationStoreProvider
  | AccessTokenProvider
  | CredentialOfferProvider
  | AuthzServerMetadataStoreProvider
  | AuthzOAuthPolicyStoreProvider
  | AuthzOAuthClientStoreProvider
  | OAuthClientAssertionJtiStoreProvider
  | NonceProvider
  | NonceStoreProvider
  | AuthzSignatureKeyStoreProvider
  | AuthzSignatureKeyProvider
  | IssuerSignatureKeyProvider
  | IssueCredentialProvider
  | DidProvider
  | VerifierMetadataStoreProvider
  | VerifierEncryptionKeyStoreProvider
  | VerifierEncryptionKeyProvider
  | VerifierSignatureKeyProvider
  | VerifierSignatureKeyStoreProvider
  | CredentialQueryProvider
  | RequestObjectStoreProvider
  | RequestObjectIdProvider
  | VerifyCredentialProvider
  | VerifyVerifiablePresentationProvider
  | JwtSignatureProvider
  | HolderBindingProvider
  | AuthzRequestJARProvider
  | VerifierCertificateStoreProvider
  | CertificateProvider
  | TransactionDataProvider
  | VerifierTransactionDataStoreProvider
  | TransactionIdProvider
  | TransactionCodeProvider
