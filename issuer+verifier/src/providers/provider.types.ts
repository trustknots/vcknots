import {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
} from '../authorization-server.types'
import { ClientId } from '../client-id.types'
import { Cnonce } from '../cnonce.types'
import {
  CredentialConfiguration,
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialIssuerMetadata,
} from '../credential-issuer.types'
import { CredentialOffer } from '../credential-offer.types'
import { CredentialQuery, CredentialQueryType } from '../credential-query.type'
import { CredentialFormats } from '../credential-request.types'
import { JwtVcJson, ProofJwt, ProofJwtHeader, VerifiableCredential } from '../credential.types'
import { Dcql } from '../dcql.type'
import { DidDocument } from '../did.types'
import { Jwk } from '../jwk.type'
import { JwtContent, JwtPayload } from '../jwt.types'
import { PreAuthorizedCode } from '../pre-authorized-code.types'
import { PresentationExchange } from '../presentation-exchange.types'
import { PresentationSubmission } from '../presentation-submission.types'
import { RequestObjectId } from '../request-object-id.types'
import { RequestObject } from '../request-object.types'
import { Certificate, SignatureKeyPair, TmpVerifierSignatureKeyPair } from '../signature-key.types'
import { DeepPartialUnknown } from '../type.utils'
import { VerifierMetadata } from '../verifier-metadata.types'

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

  save(authz: AuthorizationServerIssuer, pair: SignatureKeyPair): Promise<void>
  fetch(authz: AuthorizationServerIssuer): Promise<SignatureKeyPair>
}

export type IssuerSignatureKeyStoreProvider = {
  kind: 'issuer-signature-key-store-provider'
  name: string
  single: true

  save(issuer: CredentialIssuer, pairs: SignatureKeyPair[]): Promise<void>
  fetch(issuer: CredentialIssuer): Promise<SignatureKeyPair[]>
}

export type VerifierSignatureKeyStoreProvider = {
  kind: 'verifier-signature-key-store-provider'
  name: string
  single: true

  save(verifier: ClientId, pairs: TmpVerifierSignatureKeyPair[]): Promise<void>
  fetch(verifier: ClientId, alg: string): Promise<CryptoKey | null>
  fetchPrivate(verifier: ClientId, alg: string): Promise<CryptoKey | null>
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

export type CredentialProvider = {
  kind: 'credential-provider'
  name: string
  single: true

  verify(
    vc: string,
    issuer: string,
    presentationSubmission: PresentationSubmission
  ): Promise<boolean>
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

  verifyProof(proof: string): Promise<ProofJwt | null>
  canHandle(proofType: string): boolean
}

export type CredentialRevocationProvider = {
  kind: 'credential-revocation-provider'
  name: string
  single: true
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

  save(code: PreAuthorizedCode, options?: { ttlSec: number }): Promise<void>
  // FIXME: validation logic is a kind of business logic. so we need to move this function into [PreAuthorizedCodeProvider]
  validate(code: PreAuthorizedCode): Promise<boolean>
  delete(code: PreAuthorizedCode): Promise<void>
}

export type AccessTokenProvider = {
  kind: 'access-token-provider'
  name: string
  single: true

  createTokenPayload(
    authz: AuthorizationServerIssuer,
    code: PreAuthorizedCode,
    options?: { ttlSec: number }
  ): Promise<JwtPayload>
}

export type AuthzSignatureKeyProvider = {
  kind: 'authz-signature-key-provider'
  name: string
  single: false

  generate(): Promise<SignatureKeyPair>
  sign(
    privateKey: Jwk,
    keyAlg: string,
    jwtPayload: JwtPayload,
    jwtHeader: ProofJwtHeader
  ): Promise<string | null>
  canHandle(keyAlg: string): boolean
}

export type IssuerSignatureKeyProvider = {
  kind: 'issuer-signature-key-provider'
  name: string
  single: false

  generate(): Promise<SignatureKeyPair>
  sign(
    privateKey: Jwk,
    keyAlg: string,
    jwtPayload: JwtPayload,
    jwtHeader: ProofJwtHeader
  ): Promise<string | null>
  canHandle(keyAlg: string): boolean
}

export type VerifierSignatureKeyProvider = {
  kind: 'verifier-signature-key-provider'
  name: string
  single: false

  generate(): Promise<SignatureKeyPair>
  sign(
    verifierId: ClientId,
    keyAlg: string,
    jwtPayload: JwtPayload,
    jwtHeader: ProofJwtHeader
  ): Promise<string | null>
  canHandle(keyAlg: string): boolean
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
        }
      | {
          usePreAuth: false
          state: unknown
        }
  ): Promise<CredentialOffer>
}

export type CnonceProvider = {
  kind: 'cnonce-provider'
  name: string
  single: true

  generate(): Promise<Cnonce>
}

export type CnonceStoreProvider = {
  kind: 'cnonce-store-provider'
  name: string
  single: true

  save(cnonce: Cnonce, options?: { ttlSec: number }): Promise<void>
  // FIXME: same above
  validate(cnonce: Cnonce): Promise<boolean>
  revoke(cnonce: Cnonce): Promise<void>
}

export type IssueCredentialProvider = {
  kind: 'issue-credential-provider'
  name: string
  single: false

  createCredential(
    credentialIssuer: CredentialIssuer,
    configuration: CredentialConfiguration,
    proof: ProofJwt,
    claimsOptions?: Record<string, unknown>
  ): VerifiableCredential<JwtVcJson>
  canHandle(format: CredentialFormats): boolean
}

export type CredentialQueryGenerationOptions =
  | {
      kind: 'presentation-exchange'
      query: DeepPartialUnknown<PresentationExchange>
    }
  | {
      kind: 'dcql'
      query: DeepPartialUnknown<Dcql>
    }

export type CredentialQueryProvider = {
  kind: 'credential-query-provider'
  name: string
  single: false

  generate(options: CredentialQueryGenerationOptions): Promise<CredentialQuery>
  canHandle(query: CredentialQueryType): boolean
}

export type AuthzRequestJARProvider = {
  kind: 'authz-request-jar-provider'
  name: string
  single: false

  generate(
    verifierId: ClientId,
    requestObject: RequestObject,
    alg: string,
    nonce?: string,
    wallet_nonce?: string
  ): Promise<JwtContent>
  canHandle(clientIdScheme: string): boolean
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

export type Provider =
  | IssuerMetadataStoreProvider
  | IssuerSignatureKeyStoreProvider
  | IdentifierProvider
  | PublicKeyResolverProvider
  | CredentialFormatProvider
  | CredentialProofProvider
  | CredentialRevocationProvider
  | SignatureGenerationProvider
  | SignatureVerificationProvider
  | PreAuthorizedCodeProvider
  | PreAuthorizedCodeStoreProvider
  | AccessTokenProvider
  | CredentialOfferProvider
  | AuthzServerMetadataStoreProvider
  | CnonceProvider
  | CnonceStoreProvider
  | AuthzSignatureKeyStoreProvider
  | AuthzSignatureKeyProvider
  | IssuerSignatureKeyProvider
  | IssueCredentialProvider
  | DidProvider
  | VerifierMetadataStoreProvider
  | VerifierSignatureKeyProvider
  | VerifierSignatureKeyStoreProvider
  | CredentialQueryProvider
  | RequestObjectStoreProvider
  | RequestObjectIdProvider
  | CredentialProvider
  | JwtSignatureProvider
  | HolderBindingProvider
  | AuthzRequestJARProvider
  | VerifierCertificateStoreProvider
  | CertificateProvider
  | TransactionDataProvider
