import { Nonce } from './nonce.types'
import { exportJWK } from 'jose'
import {
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialIssuerMetadata,
} from './credential-issuer.types'
import { CredentialOffer } from './credential-offer.types'
import { CredentialRequest } from './credential-request.types'
import { CredentialResponse } from './credential-response.types'
import { err, raise } from './errors/vcknots.error'
import type { CredentialProofJwtVerifyContext } from './credential-proof-jwt.types'
import { selectProvider } from './providers/provider.utils'
import { VcknotsContext } from './vcknots.context'
import { JwtVcIssuerResponse } from './jwt-vc-issuer.types'
import { DiVpProof, Proofs, ProofTypes } from './proofs.types'
import { ProofJwt } from './credential.types'
import { calculateJwkThumbprint } from 'jose'
import { jwkSchema } from './jwk.type'

type OfferOptions =
  | {
      usePreAuth: false
      state?: unknown
      authorizationServer?: string
    }
  | {
      usePreAuth: true
      txCode?: {
        input_mode?: 'numeric' | 'text'
        length?: number
        description?: string
      }
      ttlSec?: number
      authorizationServer?: string
    }
type IssueOptions = {
  alg: string
  jti?: string
  cnonce?: {
    c_nonce_expires_in: number
  }
  claims?: Record<string, unknown>
  subject?: string
  /** OID4VCI JWT proof context: usePreAuth means the grant type is pre-authorized_code. */
  proofJwt?: {
    usePreAuth: boolean
    clientId?: string
  }
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
  throw err('invalid_credential_request', {
    message: 'Unsupported proof type',
  })
}
type CredentialOfferResponse = {
  offer: CredentialOffer
  tx_code?: string | number
}

export type IssuerFlow = {
  findIssuerMetadata(id: CredentialIssuer): Promise<CredentialIssuerMetadata | null>
  findJwtVcIssuerMetadata(id: CredentialIssuer): Promise<JwtVcIssuerResponse | null>
  createIssuerMetadata(issuer: CredentialIssuerMetadata): Promise<void>
  offerCredential(
    issuer: CredentialIssuer,
    configurations: CredentialConfigurationId[],
    options?: OfferOptions
  ): Promise<CredentialOfferResponse>
  createNonce(ttlMs?: number): Promise<string>
  validateNonce(nonce: string): Promise<boolean>
  revokeNonce(nonce: string): Promise<boolean>
  issueCredential(
    issuer: CredentialIssuer,
    credentialRequest: CredentialRequest,
    accessTokenJti: string,
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
  const credentialProof$ = context.providers.get('credential-proof-provider')
  const transactionCode$ = context.providers.get('transaction-code-provider')
  const issuanceContextStore$ = context.providers.get('issuance-context-store-provider')

  const rejectInsecureIssuerMetadata = (metadata: CredentialIssuerMetadata | null) => {
    if (metadata) {
      if (context.options?.debug) {
        return
      }
      const credentialEndpoints = [
        ['credential_endpoint', metadata.credential_endpoint],
        ['deferred_credential_endpoint', metadata.deferred_credential_endpoint],
      ].filter((url): url is [string, string] => !!url[1])

      for (const [field, url] of credentialEndpoints) {
        if (new URL(url).protocol === 'http:') {
          throw err('insecure_http_not_allowed', {
            message: `CredentialIssuerMetadata contains insecure http url in ${field}: ${url}`,
          })
        }
      }
    }
  }

  return {
    async findIssuerMetadata(id) {
      const metadata = await metadataStore$.fetch(id)
      rejectInsecureIssuerMetadata(metadata)
      return metadata
    },
    async findJwtVcIssuerMetadata(id) {
      const metadata = await metadataStore$.fetch(id)
      if (!metadata) {
        return null
      }
      rejectInsecureIssuerMetadata(metadata)
      const jwtVcIssuerMetadata: JwtVcIssuerResponse = {
        issuer: metadata.credential_issuer,
      }
      const algs = Array.from(
        Object.values(metadata.credential_configurations_supported ?? {})
          .flatMap((it) => it.credential_signing_alg_values_supported ?? [])
          .reduce((acc, it) => {
            acc.add(it)
            return acc
          }, new Set<string>())
      )
      const keyAlgs = algs.length === 0 ? ['ES256'] : algs
      const keys = (
        await Promise.all(
          keyAlgs.map(async (alg) => {
            const issuerKey = await keyStore$.fetch(id, alg)
            if (!issuerKey) {
              return null
            }
            const jwk = jwkSchema.parse(await exportJWK(issuerKey))
            if (!jwk.kid) {
              try {
                const kid = await calculateJwkThumbprint(jwk)
                return {
                  ...jwk,
                  kid,
                }
              } catch (e) {
                throw err('invalid_issuer_key', {
                  message: `Failed to calculate kid for issuer ${id} key.`,
                })
              }
            }
            return jwk
          })
        )
      ).filter((key) => key !== null)
      if (keys.length > 0) {
        jwtVcIssuerMetadata.jwks = {
          keys,
        }
      }
      return jwtVcIssuerMetadata
    },
    async createIssuerMetadata(issuer) {
      rejectInsecureIssuerMetadata(issuer)
      const current = await metadataStore$.fetch(issuer.credential_issuer)
      if (current) {
        throw err('duplicate_issuer', {
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

      await Promise.all(
        algs.map(async (alg) => {
          return await keyStore$.save(issuer.credential_issuer, alg)
        })
      )
      await metadataStore$.save(issuer)
    },
    async offerCredential(issuer, configurations, options) {
      if (options && !options.usePreAuth) {
        throw err('unsupported_grant_type', {
          message: 'Authorization code flow is not supported.',
        })
      }

      const metadata =
        (await metadataStore$.fetch(issuer)) ??
        raise('issuer_not_found', {
          message: `Issuer metadata for ${issuer} not found.`,
        })
      rejectInsecureIssuerMetadata(metadata)

      if (new Set(configurations).size !== configurations.length) {
        throw err('invalid_credential_request', {
          message: 'credential_configuration_ids must be unique.',
        })
      }

      if (options?.authorizationServer) {
        if (
          metadata.authorization_servers === undefined ||
          metadata.authorization_servers.length <= 1
        ) {
          throw err('invalid_credential_request', {
            message:
              'authorization_server can only be used when authorization_servers has multiple entries.',
          })
        }

        if (!metadata.authorization_servers.includes(options.authorizationServer)) {
          throw err('invalid_credential_request', {
            message: `Authorization server ${options.authorizationServer} is not supported by issuer ${issuer}.`,
          })
        }
      }

      for (const configId of configurations) {
        if (metadata.credential_configurations_supported[configId] === undefined) {
          throw err('unknown_credential_configuration', {
            message: `Credential configuration ${configId} is not supported by issuer ${issuer}.`,
          })
        }
      }

      let tx_code: string | number | undefined = undefined
      if (options?.txCode) {
        tx_code = transactionCode$.generate(
          options.txCode?.input_mode,
          options.txCode?.length,
          options.txCode?.description
        )
      }
      const preAuthorizedCodeStoreOptions = {
        ...(options?.ttlSec != null && { ttlSec: options.ttlSec }),
        ...(options?.txCode?.input_mode && { tx_code_input_mode: options.txCode.input_mode }),
      }

      const code = await auth$.generate()
      await codeStore$.save(code, configurations, tx_code, preAuthorizedCodeStoreOptions)
      const offer = await offer$.create(metadata, configurations, {
        usePreAuth: true,
        code,
        ...(options?.txCode && {
          txCode: {
            inputMode: options.txCode.input_mode,
            length: options.txCode.length,
            description: options.txCode.description,
          },
        }),
        ...(options?.authorizationServer && { authorizationServer: options.authorizationServer }),
      })
      return {
        offer,
        ...(tx_code !== undefined && { tx_code }),
      }
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
    async issueCredential(issuer, credentialRequest, accessTokenJti, options) {
      if (options?.subject && !isUri(options.subject)) {
        throw err('invalid_credential_request', {
          message: 'Invalid options: subject must be a URI.',
        })
      }
      const metadata =
        (await metadataStore$.fetch(issuer)) ??
        raise('issuer_not_found', {
          message: `Issuer metadata for ${issuer} not found.`,
        })
      rejectInsecureIssuerMetadata(metadata)

      if (!credentialRequest.credential_configuration_id) {
        throw err('invalid_credential_request', {
          message: 'Credential configuration id is not specified.',
        })
      }

      // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-request-2
      const credentialConfigurationSupported = metadata.credential_configurations_supported
      const configuration =
        credentialConfigurationSupported[credentialRequest.credential_configuration_id]
      if (!configuration) {
        throw err('unknown_credential_configuration', {
          message: `Credential configuration ${credentialRequest.credential_configuration_id} is not supported by issuer ${issuer}.`,
        })
      }
      const jti = accessTokenJti
      if (!jti) {
        throw err('invalid_credential_request', {
          message: 'jti is missing.',
        })
      }
      const allowedCredentialConfigurationIds = await issuanceContextStore$.fetch(jti)
      if (!allowedCredentialConfigurationIds) {
        throw err('invalid_credential_request', {
          message: 'Issuance context for this jti was not found',
        })
      }
      const requestedCredentialConfigurationId = CredentialConfigurationId(
        credentialRequest.credential_configuration_id
      )

      if (!allowedCredentialConfigurationIds.includes(requestedCredentialConfigurationId)) {
        throw err('invalid_credential_request', {
          message: 'Requested credential_configuration_id is not allowed for this jti.',
        })
      }

      const issueCredentialProvider = selectProvider(issueCredential$, configuration.format)

      const supports = Object.keys(configuration.proof_types_supported ?? {})

      let subject: string | undefined = undefined
      let verifyProof: ProofJwt | null = null
      if (credentialRequest.proofs) {
        const proofsObjects = getProofType(credentialRequest.proofs)
        if (!supports.includes(proofsObjects.proofType)) {
          throw err('invalid_credential_request', {
            message: 'Request contain no proofs supported by credential configuration.',
          })
        }

        const credentialProofProvider = selectProvider(credentialProof$, proofsObjects.proofType)
        // not support multiple proofs for now, just verify the first one
        // not support batch_credential_issuance
        for (const proof of proofsObjects.proofValue) {
          const proofJwtCtx: CredentialProofJwtVerifyContext | undefined =
            proofsObjects.proofType === ProofTypes.JWT
              ? options?.proofJwt?.usePreAuth === true
                ? {
                    usePreAuth: true,
                    credentialIssuer: metadata.credential_issuer,
                    ...(options.proofJwt.clientId ? { clientId: options.proofJwt.clientId } : {}),
                  }
                : {
                    usePreAuth: false,
                    credentialIssuer: metadata.credential_issuer,
                    clientId: options?.proofJwt?.clientId,
                  }
              : undefined
          verifyProof = await credentialProofProvider.verifyProof(proof, proofJwtCtx)
          if (!verifyProof) {
            throw err('invalid_proof', {
              message: 'Failed to verify Proof.',
            })
          }
          subject = verifyProof.header.kid

          if (options?.cnonce) {
            if (typeof verifyProof.payload.nonce === 'string') {
              const code = await cnonceStore$.validate(Nonce({ nonce: verifyProof.payload.nonce }))
              if (!code) {
                throw err('invalid_nonce', {
                  message: 'Nonce not found.',
                })
              }
              await cnonceStore$.revoke(Nonce({ nonce: verifyProof.payload.nonce }))
            }
          }
        }
      }
      if (!verifyProof) {
        throw err('invalid_credential_request', {
          message: 'Proof is required to issue credential.',
        })
      }

      const verifiableCredential = await issueCredentialProvider.createCredential(
        issuer,
        configuration,
        {
          subject: options?.subject ?? subject,
          claims: options?.claims,
          keyAlg: options?.alg ?? 'ES256',
          proofHeader: verifyProof.header,
        }
      )

      return {
        credentials: [
          {
            credential: verifiableCredential,
          },
        ],
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
