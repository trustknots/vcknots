// https://www.w3.org/TR/did-core/#did-document-properties
export type DidContextEntry = string | Record<string, unknown>
export interface DidDocument {
  '@context'?: 'https://www.w3.org/ns/did/v1' | DidContextEntry | DidContextEntry[]
  id: string
  alsoKnownAs?: string[]
  controller?: string | string[]
  verificationMethod?: VerificationMethod[]
  authentication?: (string | VerificationMethod)[]
  assertionMethod?: (string | VerificationMethod)[]
  keyAgreement?: (string | VerificationMethod)[]
  capabilityInvocation?: (string | VerificationMethod)[]
  capabilityDelegation?: (string | VerificationMethod)[]
  service?: DidService[]
  publicKey?: VerificationMethod[]
}
export interface DidService {
  id: string
  type: string
  serviceEndpoint: DidServiceEndpoint | DidServiceEndpoint[]
}

export type DidServiceEndpoint = string | Record<string, unknown>

// https://www.w3.org/TR/did-core/#verification-methods
export interface VerificationMethod {
  id: string
  type: string
  controller: string
  publicKeyBase58?: string
  publicKeyBase64?: string
  publicKeyJwk?: JsonWebKey
  publicKeyHex?: string
  publicKeyMultibase?: string
  blockchainAccountId?: string
  ethereumAddress?: string

  // ConditionalProof2022 subtypes
  conditionOr?: VerificationMethod[]
  conditionAnd?: VerificationMethod[]
  threshold?: number
  conditionThreshold?: VerificationMethod[]
  conditionWeightedThreshold?: ConditionWeightedThreshold[]
  conditionDelegated?: string
  relationshipParent?: string[]
  relationshipChild?: string[]
  relationshipSibling?: string[]
}
export interface ConditionWeightedThreshold {
  condition: VerificationMethod
  weight: number
}

// https://www.rfc-editor.org/rfc/rfc7517
export interface JsonWebKey {
  alg?: string
  crv?: string
  e?: string
  ext?: boolean
  key_ops?: string[]
  kid?: string
  kty: string
  n?: string
  use?: string
  x?: string
  y?: string
}
