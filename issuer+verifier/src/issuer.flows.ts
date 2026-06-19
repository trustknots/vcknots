import { base64url, calculateJwkThumbprint, exportJWK } from 'jose'
import { Cnonce } from './cnonce.types'
import {
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialIssuerMetadata,
} from './credential-issuer.types'
import { CredentialOffer } from './credential-offer.types'
import { CredentialFormats, CredentialRequest, ProofTypes } from './credential-request.types'
import { CredentialResponse } from './credential-response.types'
import { err, raise } from './errors/vcknots.error'
import { jwkSchema } from './jwk.type'
import { JwtVcIssuerResponse } from './jwt-vc-issuer.types'
import { buildSdJwtCredential } from './providers/issue-credential-sd-jwt.provider'
import { selectProvider } from './providers/provider.utils'
import { VcknotsContext } from './vcknots.context'

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
  const cnonce$ = context.providers.get('cnonce-provider')
  const cnonceStore$ = context.providers.get('cnonce-store-provider')
  const keyStore$ = context.providers.get('issuer-signature-key-store-provider')
  const credentialProof$ = context.providers.get('credential-proof-provider')
  const did$ = context.providers.get('did-provider')

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
            // Publish a `kid` so SD-JWT VCs (whose header carries a `kid`) can be
            // matched to the right key during verification.
            const jwk = await exportJWK(issuerKey)
            const kid = await calculateJwkThumbprint(jwk)
            return jwkSchema.parse({ ...jwk, kid })
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

      await Promise.all(
        algs.map(async (alg) => {
          return await keyStore$.save(issuer.credential_issuer, alg)
        })
      )
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
    async issueCredential(issuer, credentialRequest, options) {
      const metadata =
        (await metadataStore$.fetch(issuer)) ??
        raise('ISSUER_NOT_FOUND', {
          message: `Issuer metadata for ${issuer} not found.`,
        })

      const format = credentialRequest.format
      if (!format) {
        throw err('INVALID_REQUEST', {
          message: 'Credential request format is not specified.',
        })
      }

      // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-request-2
      const credentialConfiguration = metadata.credential_configurations_supported
      if (!credentialConfiguration) {
        throw err('UNSUPPORTED_CREDENTIAL_TYPE', {
          message: `No configuration found for: ${credentialRequest.credential_definition.type}`,
        })
      }
      const configuration = Object.values(credentialConfiguration).find((configuration) => {
        const left = new Set(configuration.credential_definition.type)
        const right = new Set(credentialRequest.credential_definition.type)
        return left.size === right.size && [...left].every((it) => right.has(it))
      })
      if (!configuration) {
        throw err('UNSUPPORTED_CREDENTIAL_TYPE', {
          message: `No configuration found for: ${credentialRequest.credential_definition.type}`,
        })
      }

      const supports = Object.keys(configuration.proof_types_supported ?? {})

      const proof = credentialRequest.proof
      if (proof && proof.proof_type !== ProofTypes.JWT) {
        throw err('UNSUPPORTED_CREDENTIAL_TYPE', {
          message: `Credential proof type ${proof?.proof_type} is not supported.`,
        })
      }
      if (!proof || !proof.proof_type || !proof[proof.proof_type] || !proof.jwt) {
        throw err('INVALID_CREDENTIAL_REQUEST', {
          message: 'No proof object found.',
        })
      }
      if (!supports.includes(proof.proof_type)) {
        throw err('INVALID_CREDENTIAL_REQUEST', {
          message: 'Request contain no proofs supported by credential configuration.',
        })
      }

      const proofJwt = proof.jwt
      const credentialProofProvider = selectProvider(credentialProof$, proof.proof_type)
      const verifyProof = await credentialProofProvider.verifyProof(proofJwt)
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

      let nonce = undefined
      if (options?.cnonce) {
        if (typeof verifyProof.payload.nonce === 'string') {
          const code = await cnonceStore$.validate(Cnonce(verifyProof.payload.nonce))
          if (!code) {
            throw err('INVALID_PROOF', {
              message: 'Nonce not found.',
            })
          }
          await cnonceStore$.revoke(Cnonce(verifyProof.payload.nonce))
          nonce = await cnonce$.generate()
          await cnonceStore$.save(Cnonce(nonce))
        }
      }

      const keyAlg = options?.alg ?? 'ES256'
      if (
        !configuration.credential_signing_alg_values_supported ||
        !configuration.credential_signing_alg_values_supported.includes(keyAlg)
      ) {
        throw err('UNSUPPORTED_ISSUER_KEY_ALG', {
          message: 'Unsupported key algorithm.',
        })
      }

      // SD-JWT VC keeps claim values out of the signed body and binds them to the
      // holder key, so it follows a dedicated assembly path instead of the W3C
      // JWT VC one below.
      if (format === CredentialFormats.DC_SD_JWT) {
        const holderKid = verifyProof.header.kid
        const didSplit = holderKid.split(':')
        const didProvider = selectProvider(did$, didSplit[1])
        const holderDidDoc = await didProvider.resolveDid(holderKid)
        const holderJwk = holderDidDoc?.verificationMethod?.[0]?.publicKeyJwk
        if (!holderJwk) {
          throw err('INVALID_PROOF', {
            message: 'Cannot resolve holder key for SD-JWT key binding.',
          })
        }

        // The SD-JWT `vct` is the configuration's specific (non-base) type.
        const types = configuration.credential_definition.type
        const vct = types.find((it) => it !== 'VerifiableCredential') ?? types[0]

        // Collect the disclosable claims declared by the configuration.
        const subject = configuration.credential_definition.credentialSubject ?? {}
        const claims: Record<string, unknown> = {}
        for (const [key, definition] of Object.entries(subject)) {
          if (options?.claims && key in options.claims) {
            const value = options.claims[key]
            claims[key] =
              definition.value_type === 'number'
                ? Number(value)
                : definition.value_type === 'string'
                  ? String(value)
                  : value
          } else if (definition.mandatory === true) {
            throw err('INVALID_CLAIMS', {
              message: `Claim ${key} is defined as mandatory but was not provided.`,
            })
          }
        }

        const issuerKey = await keyStore$.fetch(issuer, keyAlg)
        if (!issuerKey) {
          throw err('AUTHZ_ISSUER_KEY_NOT_FOUND', {
            message: 'Issuer key not found.',
          })
        }
        // Must match the `kid` published in the issuer JWKS (see jwt-vc-issuer).
        const issuerKid = await calculateJwkThumbprint(await exportJWK(issuerKey))

        const credential = await buildSdJwtCredential({
          issuer,
          vct,
          alg: keyAlg,
          kid: issuerKid,
          holderJwk,
          claims,
          sign: (payload, header) =>
            keyStore$.sign(
              issuer,
              keyAlg,
              payload as Parameters<typeof keyStore$.sign>[2],
              header as Parameters<typeof keyStore$.sign>[3]
            ),
        })

        return {
          credential,
          c_nonce: nonce,
          c_nonce_expires_in: options?.cnonce?.c_nonce_expires_in ?? 86400,
        }
      }

      const issueCredentialProvider = selectProvider(issueCredential$, format)
      const verifiableCredential = issueCredentialProvider.createCredential(
        issuer,
        configuration,
        verifyProof,
        options?.claims
      )
      const jwtHeader = {
        alg: keyAlg,
        typ: 'JWT',
      }
      const jwtPayload = {
        vc: verifiableCredential,
        iss: verifiableCredential.issuer,
        sub: verifyProof.header.kid,
      }
      const issuerKeys = await keyStore$.fetch(issuer, keyAlg)
      if (!issuerKeys) {
        throw err('AUTHZ_ISSUER_KEY_NOT_FOUND', {
          message: 'Issuer key not found.',
        })
      }
      const signature = await keyStore$.sign(issuer, keyAlg, jwtPayload, jwtHeader)
      if (!signature) {
        throw err('INTERNAL_SERVER_ERROR', {
          message: 'Cannot sign credentials.',
        })
      }
      const encode = (x: unknown) => base64url.encode(JSON.stringify(x))
      const credential = `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`

      return {
        credential: credential,
        c_nonce: nonce,
        c_nonce_expires_in: options?.cnonce?.c_nonce_expires_in ?? 86400,
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
