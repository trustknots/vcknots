import { base64url } from 'jose'
import { Nonce } from './nonce.types'
import {
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialIssuerMetadata,
} from './credential-issuer.types'
import { CredentialOffer } from './credential-offer.types'
import { CredentialRequest } from './credential-request.types'
import { CredentialResponse } from './credential-response.types'
import { err, raise } from './errors/vcknots.error'
import { selectProvider } from './providers/provider.utils'
import { VcknotsContext } from './vcknots.context'
import { JwtVcIssuerResponse } from './jwt-vc-issuer.types'
import { DiVpProof, Proofs, ProofTypes } from './proofs.types'
import { ProofJwt } from './credential.types'

type OfferOptions =
  | {
      usePreAuth: false
      state?: unknown
    }
  | {
      usePreAuth: true
      txCode?: {
        inputMode?: 'numeric' | 'text'
        length?: number
        description?: string
      }
    }
type IssueOptions = {
  alg: string
  cnonce?: {
    c_nonce_expires_in: number
  }
  claims?: Record<string, unknown>
  subject?: string
}

export const isUri = (value: string): boolean => {
  if (!value || /\s/.test(value)) {
    return false
  }

  return /^[a-zA-Z][a-zA-Z0-9+.-]*:[^\s]+$/.test(value)
}
function getProofType(
  proofs: Proofs
):
  | { proofType: 'jwt'; proofValue: string[] }
  | { proofType: 'di_vp'; proofValue: DiVpProof[] }
  | { proofType: 'attestation'; proofValue: string[] } {
  if (ProofTypes.JWT in proofs) {
    return {
      proofType: ProofTypes.JWT,
      proofValue: proofs.jwt,
    }
  }
  if (ProofTypes.DI_VP in proofs) {
    return {
      proofType: ProofTypes.DI_VP,
      proofValue: proofs.di_vp,
    }
  }
  if (ProofTypes.ATTESTATION in proofs) {
    return {
      proofType: ProofTypes.ATTESTATION,
      proofValue: proofs.attestation,
    }
  }
  throw new Error('Unsupported proof type')
}

export type IssuerFlow = {
  findIssuerMetadata(id: CredentialIssuer): Promise<CredentialIssuerMetadata | null>
  findJwtVcIssuerMetadata(id: CredentialIssuer): Promise<JwtVcIssuerResponse | null>
  createIssuerMetadata(issuer: CredentialIssuerMetadata): Promise<void>
  offerCredential(
    issuer: CredentialIssuer,
    configurations: CredentialConfigurationId[],
    options?: OfferOptions
  ): Promise<CredentialOffer>
  createNonce(ttlMs?: number): Promise<string>
  validateNonce(nonce: string): Promise<boolean>
  revokeNonce(nonce: string): Promise<boolean>
  issueCredential(
    issuer: CredentialIssuer,
    credentialRequest: CredentialRequest,
    options?: IssueOptions
  ): Promise<CredentialResponse>
}

export const initializeIssuerFlow = (context: VcknotsContext): IssuerFlow => {
  const metadataStore$ = context.providers.get('issuer-metadata-store-provider')
  const auth$ = context.providers.get('pre-authorized-code-provider')
  const offer$ = context.providers.get('credential-offer-provider')
  const codeStore$ = context.providers.get('pre-authorized-code-store-provider')
  const issueCredential$ = context.providers.get('issue-credential-provider')
  const cnonce$ = context.providers.get('nonce-provider')
  const cnonceStore$ = context.providers.get('nonce-store-provider')
  const keyStore$ = context.providers.get('issuer-signature-key-store-provider')
  const key$ = context.providers.get('issuer-signature-key-provider')
  const credentialProof$ = context.providers.get('credential-proof-provider')

  return {
    async findIssuerMetadata(id) {
      const metadata = await metadataStore$.fetch(id)
      return metadata
    },
    async findJwtVcIssuerMetadata(id) {
      const metadata = await metadataStore$.fetch(id)
      if (!metadata) {
        return null
      }
      const jwtVcIssuerMetadata: JwtVcIssuerResponse = {
        issuer: metadata.credential_issuer,
      }
      const issuerKeys = await keyStore$.fetch(id)
      if (issuerKeys && issuerKeys.length > 0) {
        jwtVcIssuerMetadata.jwks = {
          keys: issuerKeys.map((keypair) => {
            const { publicKey } = keypair
            return publicKey
          }),
        }
      }
      return jwtVcIssuerMetadata
    },
    async createIssuerMetadata(issuer) {
      const current = await metadataStore$.fetch(issuer.credential_issuer)
      if (current) {
        throw err('DUPLICATE_ISSUER', {
          message: `issuer ${issuer.credential_issuer} is already registered.`,
        })
      }
      const algs = Array.from(
        Object.values(issuer.credential_configurations_supported ?? {})
          .flatMap((it) => it.credential_signing_alg_values_supported ?? [])
          .reduce((acc, it) => {
            acc.add(it)
            return acc
          }, new Set<string>())
      )

      const pairs = await Promise.all(
        algs.map(async (alg) => {
          const provider = selectProvider(key$, alg)
          return await provider.generate()
        })
      )

      await keyStore$.save(issuer.credential_issuer, pairs)
      await metadataStore$.save(issuer)
    },
    async offerCredential(issuer, configurations, options) {
      if (options && !options.usePreAuth) {
        throw err('FEATURE_NOT_IMPLEMENTED_YET', {
          message: 'Authorization code flow is not supported.',
        })
      }

      const metadata =
        (await metadataStore$.fetch(issuer)) ??
        raise('ISSUER_NOT_FOUND', {
          message: `Issuer metadata for ${issuer} not found.`,
        })

      for (const configId of configurations) {
        if (metadata.credential_configurations_supported[configId] === undefined) {
          throw err('UNSUPPORTED_CREDENTIAL_TYPE', {
            message: `Credential configuration ${configId} is not supported by issuer ${issuer}.`,
          })
        }
      }

      const code = await auth$.generate()
      await codeStore$.save(code)
      const offer = await offer$.create(metadata, configurations, {
        usePreAuth: true,
        code,
        ...(options?.txCode && { txCode: options.txCode }),
      })
      return offer
    },
    async createNonce(ttlMs) {
      const nonce = await cnonce$.generate({ nonce_expires_in: ttlMs })
      await cnonceStore$.save(nonce)
      return nonce.nonce
    },
    async validateNonce(nonce) {
      const lookupNonce = Nonce({ nonce })
      return cnonceStore$.validate(lookupNonce)
    },
    async revokeNonce(nonce) {
      const lookupNonce = Nonce({ nonce })
      return cnonceStore$.revoke(lookupNonce)
    },
    async issueCredential(issuer, credentialRequest, options) {
      if (options?.subject && !isUri(options.subject)) {
        throw err('INVALID_REQUEST', {
          message: 'Invalid options: subject must be a URI.',
        })
      }
      const metadata =
        (await metadataStore$.fetch(issuer)) ??
        raise('ISSUER_NOT_FOUND', {
          message: `Issuer metadata for ${issuer} not found.`,
        })

      if (!credentialRequest.credential_configuration_id) {
        throw err('INVALID_REQUEST', {
          message: 'Credential configuration id is not specified.',
        })
      }

      // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-request-2
      const credentialConfiguration = metadata.credential_configurations_supported
      const configuration = credentialConfiguration[credentialRequest.credential_configuration_id]
      if (!configuration) {
        throw err('UNSUPPORTED_CREDENTIAL_TYPE', {
          message: `Credential configuration ${credentialRequest.credential_configuration_id} is not supported by issuer ${issuer}.`,
        })
      }
      const issueCredentialProvider = selectProvider(issueCredential$, configuration.format)

      const supports = Object.keys(configuration.proof_types_supported ?? {})

      let subject: string | undefined = undefined
      let verifyProof: ProofJwt | null = null
      let nonce = undefined
      if (credentialRequest.proofs) {
        const proofsObjects = getProofType(credentialRequest.proofs)
        if (!supports.includes(proofsObjects.proofType)) {
          throw err('INVALID_CREDENTIAL_REQUEST', {
            message: 'Request contain no proofs supported by credential configuration.',
          })
        }

        const credentialProofProvider = selectProvider(credentialProof$, proofsObjects.proofType)
        for (const proof of proofsObjects.proofValue) {
          verifyProof = await credentialProofProvider.verifyProof(proof)
          if (!verifyProof) {
            throw err('INVALID_PROOF', {
              message: 'Failed to verify Proof.',
            })
          }
          if (!verifyProof.header.kid) {
            throw err('INVALID_PROOF', {
              message: 'Unsupported proof header.',
            })
          }
          subject = verifyProof.header.kid

          if (options?.cnonce) {
            if (typeof verifyProof.payload.nonce === 'string') {
              const code = await cnonceStore$.validate(Nonce({ nonce: verifyProof.payload.nonce }))
              if (!code) {
                throw err('INVALID_PROOF', {
                  message: 'Nonce not found.',
                })
              }
              await cnonceStore$.revoke(Nonce({ nonce: verifyProof.payload.nonce }))
              nonce = await cnonce$.generate()
              await cnonceStore$.save(Nonce(nonce))
            }
          }
        }
      }
      if (!verifyProof) {
        throw err('INVALID_CREDENTIAL_REQUEST', {
          message: 'Proof is required to issue credential.',
        })
      }

      const verifiableCredential = issueCredentialProvider.createCredential(issuer, configuration, {
        subject: options?.subject ?? subject,
        claims: options?.claims,
      })
      const keyAlg = options?.alg ?? 'ES256'
      if (
        configuration.credential_signing_alg_values_supported &&
        !configuration.credential_signing_alg_values_supported.includes(keyAlg)
      ) {
        throw err('UNSUPPORTED_ISSUER_KEY_ALG', {
          message: 'Unsupported key algorithm.',
        })
      }
      const jwtHeader = {
        alg: keyAlg,
        typ: 'JWT',
      }
      const jwtPayload = {
        vc: verifiableCredential,
        iss: verifiableCredential.issuer,
        sub: options?.subject ?? subject,
      }
      const issuerKeys = await keyStore$.fetch(issuer)
      const keys = issuerKeys.find((keypair) => keypair.privateKey.alg === keyAlg)
      if (!keys) {
        throw err('AUTHZ_ISSUER_KEY_NOT_FOUND', {
          message: 'Issuer key not found.',
        })
      }
      const keyProvider = selectProvider(key$, keyAlg)
      const signature = await keyProvider.sign(keys.privateKey, keyAlg, jwtPayload, jwtHeader)
      if (!signature) {
        throw err('INTERNAL_SERVER_ERROR', {
          message: 'Cannot sign credentials.',
        })
      }
      const encode = (x: unknown) => base64url.encode(JSON.stringify(x))
      const credential = `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`

      return {
        credential: credential,
        c_nonce: nonce?.nonce,
        c_nonce_expires_in: nonce?.nonce_expires_in ?? options?.cnonce?.c_nonce_expires_in ?? 86400,
      }
    },
  }
}

export {
  CredentialIssuer,
  CredentialIssuerMetadata,
  CredentialConfigurationId,
} from './credential-issuer.types'
export { issueCredentialJwt } from './providers/issue-credential-jwt-vc-json.provider'
export { CredentialRequest } from './credential-request.types'
