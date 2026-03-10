import { base64url, calculateJwkThumbprint } from 'jose'
import { SDJwtInstance } from '@sd-jwt/core'
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs'
import { Cnonce } from './cnonce.types'
import {
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialIssuerMetadata,
} from './credential-issuer.types'
import { CredentialOffer } from './credential-offer.types'
import { CredentialRequest, ProofTypes } from './credential-request.types'
import { CredentialResponse } from './credential-response.types'
import { err, raise } from './errors/vcknots.error'
import { selectProvider } from './providers/provider.utils'
import { VcknotsContext } from './vcknots.context'
import { JwtVcIssuerResponse } from './jwt-vc-issuer.types'

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
      // Enrich JWKS keys with kid (JWK thumbprint) so verifiers can match
      // the kid in SD-JWT headers to the correct issuer public key
      const issuerKeys = await keyStore$.fetch(id)
      if (issuerKeys && issuerKeys.length > 0) {
        jwtVcIssuerMetadata.jwks = {
          keys: await Promise.all(
            issuerKeys.map(async (keypair) => {
              const { publicKey } = keypair
              if (publicKey.kid) {
                return publicKey
              }
              try {
                const kid = await calculateJwkThumbprint(publicKey)
                return { ...publicKey, kid }
              } catch {
                return publicKey
              }
            })
          ),
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
      // Accept kid (DID-based) or jwk (raw public key) as proof of possession.
      // dc+sd-jwt proofs use jwk for the cnf claim; jwt_vc_json proofs use kid.
      if (!verifyProof.header.kid && !verifyProof.header.jwk) {
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

      const issuerKeys = await keyStore$.fetch(issuer)
      const keys = issuerKeys.find((keypair) => keypair.privateKey.alg === keyAlg)
      if (!keys) {
        throw err('AUTHZ_ISSUER_KEY_NOT_FOUND', {
          message: 'Issuer key not found.',
        })
      }

      // dc+sd-jwt: issue as SD-JWT with cnf claim for key binding
      if (format === 'dc+sd-jwt') {
        const holderJwk = verifyProof.header.jwk
        const vct = configuration.vct ?? 'VerifiableCredential'

        // Build claims from credential definition, coercing values by declared type
        const sdJwtClaims: Record<string, unknown> = {}
        const credentialSubject = configuration.credential_definition.credentialSubject
        if (credentialSubject && Object.keys(credentialSubject).length > 0 && options?.claims) {
          for (const [key, value] of Object.entries(credentialSubject)) {
            if (value.mandatory === true && !(key in options.claims)) {
              throw err('INVALID_CLAIMS', {
                message: `Mandatory claim "${key}" is missing.`,
              })
            }
            if (key in options.claims) {
              if (value.value_type === 'string') {
                sdJwtClaims[key] = String(options.claims[key])
              } else if (value.value_type === 'number') {
                sdJwtClaims[key] = Number(options.claims[key])
              } else {
                sdJwtClaims[key] = options.claims[key]
              }
            }
          }
        }

        const kid = await calculateJwkThumbprint(keys.publicKey)
        const signer = await ES256.getSigner(keys.privateKey)
        const sdJwtInstance = new SDJwtInstance({
          hasher: digest,
          signer,
          saltGenerator: () => generateSalt(8),
          signAlg: ES256.alg,
        })

        const sdJwtPayload = {
          iss: issuer,
          vct,
          iat: Math.floor(Date.now() / 1000),
          sub: verifyProof.header.kid,
          ...(holderJwk ? { cnf: { jwk: holderJwk } } : {}),
          ...sdJwtClaims,
        }

        const sdJwt = await sdJwtInstance.issue(sdJwtPayload, undefined, {
          header: { kid },
        })

        return {
          credential: sdJwt,
          c_nonce: nonce,
          c_nonce_expires_in: options?.cnonce?.c_nonce_expires_in ?? 86400,
        }
      }

      // jwt_vc_json: wrap credential in JWT envelope using format-specific provider.
      // selectProvider is called here (not earlier) because no provider handles dc+sd-jwt.
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
