import base64url from 'base64url'
import { AuthorizationRequest } from './authorization-request.types'
import { AuthorizationResponse } from './authorization-response.types'
import { ClientId } from './client-id.types'
import { Dcql } from './dcql.type'
import { err, raise } from './errors/vcknots.error'
import { VerifyVerifiablePresentationVerifyOptions } from './providers'
import { selectProvider } from './providers/provider.utils'
import { RequestObject } from './request-object.types'
import { DeepPartialUnknown } from './type.utils'
import { VcknotsContext } from './vcknots.context'
import { VerifierMetadata } from './verifier-metadata.types'
import { RequestObjectId } from './request-object-id.types'
import { Certificate } from './signature-key.types'
import { Jwk } from './jwk.type'
import { importSPKI } from 'jose'
import { ClientIdentifier } from './client-id-scheme.types'
import { Cnonce } from './cnonce.types'
import { VpTokenPayload } from './presentation.types'
import { TransactionId, TransactionRecord } from './transaction-id.types'

type CreateVerifierMetadataOptionsBase = {
  format: 'pem' | 'jwk'
  alg: string
  kid?: string
  encryptionPublicKey?: EncryptionPublicKeyOptions
}
type EncryptionPublicKeyOptions =
  | {
      format: 'pem'
      alg: string
      kid?: string
      publicKey: string
    }
  | {
      format: 'jwk'
      alg: string
      kid?: string
      publicKey: Jwk
    }
type CreateVerifierMetadataOptionsWithCert = CreateVerifierMetadataOptionsBase & {
  privateKey: string | Jwk
  certificate: string | string[]
}
type CreateVerifierMetadataOptionsWithPubKey = CreateVerifierMetadataOptionsBase & {
  privateKey: string | Jwk
  publicKey: string | Jwk
}
export type CreateVerifierMetadataOptions =
  | CreateVerifierMetadataOptionsWithPubKey
  | CreateVerifierMetadataOptionsWithCert
export type CreateAuthzRequestOptions = {
  state?: string
  scope?: string
  response_uri?: string
  base_url?: string
  request_uri?: string
  transaction_data?: { type: string; transaction_data_hashes_alg?: string[] }
}
export type VerifyPresentationOptions = {
  isKbJwt?: boolean
  expectedTransactionDataHashes?: string[]
}
export type FindRequestObjectOptions = {
  alg?: string
  // https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.11 is not supported
  // wallet_metadata? :
  // wallet_nonce?: string
}

type CreateAuthzRequestResponse = {
  request: AuthorizationRequest
  transactionId: string
}

export type VerifierFlow = {
  findVerifierCertificate: (id: ClientId) => Promise<Certificate | null>
  findVerifierMetadata: (verifierId: ClientId) => Promise<VerifierMetadata | null>
  createVerifierMetadata(
    verifierId: ClientId,
    metadata: VerifierMetadata,
    options?: CreateVerifierMetadataOptions
  ): Promise<void>
  createAuthzRequest(
    verifierId: ClientId,
    response_type: 'vp_token',
    client_id: ClientIdentifier,
    response_mode: 'direct_post' | 'query' | 'fragment' | 'dc_api.jwt' | 'dc_api',
    query: DeepPartialUnknown<Dcql>,
    isRequestUri: boolean,
    options: CreateAuthzRequestOptions
  ): Promise<CreateAuthzRequestResponse>
  findRequestObject(
    verifierId: ClientId,
    objectId: RequestObjectId,
    options?: FindRequestObjectOptions
  ): Promise<string>
  getTransaction(transactionId: string): Promise<{
    clientId: ClientIdentifier
    state?: string
    dcqlQuery: Dcql
    expiresAt: number
  }>
  deleteTransaction(transactionId: string): Promise<void>
  verifyPresentations: (
    response: AuthorizationResponse,
    transactionId: string,
    options?: VerifyPresentationOptions
  ) => Promise<Record<string, VpTokenPayload[]>>
}

export const initializeVerifierFlow = (context: VcknotsContext): VerifierFlow => {
  const cnonce$ = context.providers.get('cnonce-provider')
  const nonceStore$ = context.providers.get('cnonce-store-provider')
  const query$ = context.providers.get('credential-query-provider')
  const verifierMetadata$ = context.providers.get('verifier-metadata-store-provider')
  const keyStore$ = context.providers.get('verifier-signature-key-store-provider')
  const encryptionKeyStore$ = context.providers.get('verifier-encryption-key-store-provider')
  const requestObjectId$ = context.providers.get('request-object-id-provider')
  const requestObjectStore$ = context.providers.get('request-object-store-provider')
  const authzRequestJAR$ = context.providers.get('authz-request-jar-provider')
  const certificateStore$ = context.providers.get('verifier-certificate-store-provider')
  const certificate$ = context.providers.get('certificate-provider')
  const transactionData$ = context.providers.get('transaction-data-provider')
  const verifiablePresentation$ = context.providers.get('verify-verifiable-presentation-provider')
  const transactionId$ = context.providers.get('transaction-id-provider')
  const transactionDataStore$ = context.providers.get('verifier-transaction-store-provider')

  return {
    async findVerifierCertificate(id) {
      return certificateStore$.fetch(id)
    },
    async findVerifierMetadata(verifierId) {
      return verifierMetadata$.fetch(verifierId)
    },
    async createVerifierMetadata(verifierId, metadata, options) {
      const current = await verifierMetadata$.fetch(verifierId)
      if (current) {
        throw err('DUPLICATE_VERIFIER', {
          message: `verifier ${verifierId} is already registered.`,
        })
      }
      const verifierMetadata = metadata
      let keyPairsToSave:
        | {
            format: 'pem' | 'jwk'
            declaredAlg: string
            kid?: string
            publicKey?: string | Jwk
            privateKey: string | Jwk
          }
        | undefined
      let certificatesToSave: Certificate | undefined
      let keyAlg: string | undefined = options?.alg
      if (!options || !keyAlg) {
        // create new signing key pair (not support x509)
        keyAlg = metadata.authorization_signed_response_alg ?? 'ES256'
        await keyStore$.save(verifierId, keyAlg)
        verifierMetadata.authorization_signed_response_alg = keyAlg
      } else if ('publicKey' in options && options.publicKey !== undefined) {
        // use provided signing key pair (not support x509)
        if (!keyAlg) {
          throw err('INTERNAL_SERVER_ERROR', {
            message: 'alg is required in the provided publicKey.',
          })
        }
        if (options.format === 'jwk' && typeof options.publicKey !== 'string') {
          verifierMetadata.authorization_signed_response_alg = keyAlg
        } else if (options.format === 'jwk') {
          throw err('INVALID_OPTIONS', {
            message: 'publicKey must be a JWK when format is jwk.',
          })
        } else if (options.format === 'pem' && typeof options.publicKey === 'string') {
          await importSPKI(options.publicKey, keyAlg)
          verifierMetadata.authorization_signed_response_alg = keyAlg
        } else {
          throw err('INVALID_OPTIONS', {
            message: 'publicKey must be a PEM string when format is pem.',
          })
        }
        keyPairsToSave = {
          format: options.format,
          declaredAlg: keyAlg,
          kid: options.kid,
          publicKey: options.publicKey,
          privateKey: options.privateKey,
        }
      } else if ('certificate' in options && options.certificate !== undefined) {
        // use provided signing key pair and x509 certificate
        // password protected private key is not supported
        if (!keyAlg) {
          throw err('INTERNAL_SERVER_ERROR', {
            message: 'alg is required in the provided privateKey.',
          })
        }
        const certificateChain =
          typeof options.certificate === 'string' ? [options.certificate] : options.certificate
        const certificates = Certificate(certificateChain)
        const certValid = await certificate$.validate(certificates)
        if (!certValid) {
          throw err('INVALID_CERTIFICATE', {
            message: 'The provided certificate is not valid.',
          })
        }
        const certificate = certificates[0]
        const publicKey = await certificate$.getPublicKey(certificate)
        await importSPKI(publicKey, keyAlg)
        verifierMetadata.authorization_signed_response_alg = keyAlg
        certificatesToSave = certificates
        keyPairsToSave = {
          format: options.format,
          declaredAlg: keyAlg,
          kid: options.kid,
          publicKey: publicKey,
          privateKey: options.privateKey,
        }
      }

      const encryptionKeyAlg = 'RSA-OAEP-256'
      await encryptionKeyStore$.save(verifierId, encryptionKeyAlg)
      const encryptionPublicJwk = await encryptionKeyStore$.fetch(verifierId, encryptionKeyAlg)
      if (!encryptionPublicJwk) {
        throw err('INTERNAL_SERVER_ERROR', {
          message: 'Failed to generate encryption key pair.',
        })
      }

      verifierMetadata.jwks = {
        keys: [encryptionPublicJwk],
      }

      if (certificatesToSave) {
        await certificateStore$.save(verifierId, certificatesToSave)
      }
      if (keyPairsToSave) {
        await keyStore$.save(verifierId, keyAlg, keyPairsToSave)
      }
      await verifierMetadata$.save(verifierId, verifierMetadata)
    },
    async createAuthzRequest(
      verifierId,
      response_type,
      client_id,
      response_mode,
      query,
      isRequestUri,
      options
    ) {
      const client_id_scheme = client_id.split(':')[0]

      if (client_id_scheme === 'x509_san_dns' || client_id_scheme === 'x509_san_uri') {
        const certificate = await certificateStore$.fetch(verifierId)
        if (!certificate) {
          throw err('CERTIFICATE_NOT_FOUND', {
            message: 'verifier certificate is not found.',
          })
        }
      }

      const metadata = (await verifierMetadata$.fetch(verifierId)) ?? raise('VERIFIER_NOT_FOUND')

      const parsedQuery = await query$.generate(query)

      const transaction_data: string[] = []
      const credentialIds: string[] = []
      let isDcSDJwtRequested = false
      // Validate: Metadata supports format
      const vpFormats = Object.keys(metadata.vp_formats)
      if (parsedQuery.dcql_query) {
        for (const credential of parsedQuery.dcql_query.credentials) {
          if (!vpFormats.includes(credential.format)) {
            throw err('VERIFIER_VP_FORMATS_NOT_SUPPORTED', {
              message: `The vp_format ${credential.format} is not supported by the verifier.`,
            })
          }
          if (credential.format === 'dc+sd-jwt') {
            isDcSDJwtRequested = true
            credentialIds.push(credential.id)
          }
        }
        if (isDcSDJwtRequested && options.transaction_data) {
          transaction_data.push(
            transactionData$.generate(options.transaction_data.type, credentialIds)
          )
        }
      }

      const responseUri = options.response_uri ?? `${verifierId}/post`

      // when using request_uri
      if (isRequestUri ?? true) {
        const authzRequestJAR = selectProvider(authzRequestJAR$, client_id_scheme)
        if (!authzRequestJAR) {
          throw err('UNSUPPORTED_CLIENT_ID_SCHEME', {
            message: 'client_id_scheme is not supported.',
          })
        }
        if (!options.base_url) {
          throw err('INVALID_REQUEST', {
            message: 'base_url is required when is_request_uri is true',
          })
        }

        const transactionId = await transactionId$.generate()
        const nonce = await cnonce$.generate()
        await nonceStore$.save(nonce)
        await transactionDataStore$.save(
          transactionId,
          TransactionRecord({
            dcqlQuery: parsedQuery,
            clientId: client_id,
            verifierId,
            state: options.state,
            nonce,
          })
        )

        // create RequestObjectId
        const requestObjectId = await requestObjectId$.generate()

        // create RequestObjectを作成(generate iat and nonce when creating the JAR)
        const requestObject = RequestObject({
          response_type: response_type,
          client_id: client_id,
          scope: options.scope,
          state: options.state,
          response_uri: responseUri,
          iss: client_id,
          aud: 'https://self-issued.me/v2',
          client_metadata: metadata,
          response_mode: response_mode || 'direct_post',
          nonce,
          ...parsedQuery,
          ...(transaction_data.length > 0 ? { transaction_data } : {}),
        })
        await requestObjectStore$.save(requestObjectId, requestObject)

        return {
          request: AuthorizationRequest({
            client_id: client_id,
            request_uri: options.request_uri
              ? `${options.request_uri}/${encodeURIComponent(requestObjectId)}`
              : `${options.base_url}/request.jwt/${encodeURIComponent(requestObjectId)}`,
          }),
          transactionId,
        }
      }

      const transactionId = await transactionId$.generate()
      const nonce = await cnonce$.generate()
      await nonceStore$.save(nonce)
      await transactionDataStore$.save(
        transactionId,
        TransactionRecord({
          dcqlQuery: parsedQuery,
          clientId: client_id,
          verifierId,
          state: options.state,
          nonce,
        })
      )

      return {
        request: AuthorizationRequest({
          client_id: client_id,
          response_uri: responseUri,
          response_type: response_type,
          response_mode: response_mode || 'direct_post',
          client_id_scheme: client_id_scheme,
          client_metadata: metadata,
          nonce,
          state: options.state,
          ...parsedQuery,
          ...(transaction_data.length > 0 ? { transaction_data } : {}),
        }),
        transactionId,
      }
    },
    async findRequestObject(verifierId, objectId) {
      const metadata = (await verifierMetadata$.fetch(verifierId)) ?? raise('VERIFIER_NOT_FOUND')
      const keyAlg = metadata.authorization_signed_response_alg ?? 'ES256'

      const requestObject = await requestObjectStore$.fetch(objectId)
      if (!requestObject) {
        throw raise('REQUEST_OBJECT_NOT_FOUND', {
          message: 'Request object is not found.',
        })
      }

      const clientId = requestObject.client_id
      const client_id_scheme = clientId.split(':')[0]
      const authzRequestJAR = selectProvider(authzRequestJAR$, client_id_scheme)
      if (!authzRequestJAR) {
        throw raise('PROVIDER_NOT_FOUND', {
          message: 'Authorization request JAR provider is not found.',
        })
      }
      // wallet_nonce is not supported
      const walletNonce = undefined

      const { header, payload } = await authzRequestJAR.generate(
        verifierId,
        requestObject,
        keyAlg,
        walletNonce
      )

      // const keyProvider = selectProvider(key$, keyAlg)
      // if (!keyProvider) {
      //   throw raise('AUTHZ_VERIFIER_KEY_NOT_FOUND', {
      //     message: `Verifier signature key provider for ${keyAlg} is not found.`,
      //   })
      // }
      const signature = await keyStore$.sign(verifierId, keyAlg, payload, header)
      if (!signature) {
        throw err('AUTHZ_VERIFIER_KEY_NOT_FOUND', {
          message: `Verifier signing key for ${keyAlg} is not found.`,
        })
      }

      await requestObjectStore$.delete(objectId)

      const encode = (x: unknown) => base64url.encode(JSON.stringify(x))

      return `${encode(header)}.${encode(payload)}.${signature}`
    },
    async getTransaction(transactionId) {
      const transaction = await transactionDataStore$.fetch(TransactionId(transactionId))
      if (!transaction) {
        throw err('TRANSACTION_ID_NOT_FOUND', {
          message: 'transaction_id is unknown or already removed',
        })
      }
      return {
        clientId: transaction.clientId,
        state: transaction.state,
        dcqlQuery: transaction.dcqlQuery,
        expiresAt: transaction.transaction_data_expires_at,
      }
    },
    async deleteTransaction(transactionId) {
      await transactionDataStore$.delete(TransactionId(transactionId))
    },
    async verifyPresentations(response, transactionId, options) {
      if (!transactionId) {
        throw err('ILLEGAL_ARGUMENT', {
          message: 'transaction_id is required.',
        })
      }
      const transaction = await transactionDataStore$.fetch(TransactionId(transactionId))
      if (!transaction) {
        throw err('TRANSACTION_ID_NOT_FOUND', {
          message: 'Transaction is not found.',
        })
      }
      if (!(await verifierMetadata$.fetch(transaction.verifierId))) {
        throw raise('VERIFIER_NOT_FOUND', {
          message: 'verifier is not found.',
        })
      }
      if (transaction.state !== undefined) {
        if (response.state !== transaction.state) {
          throw err('INVALID_REQUEST', {
            message: 'unknown or expired state.',
          })
        }
      }

      const expectedAud = transaction.clientId
      const expectedNonce = transaction.nonce
      const dcql_query = transaction.dcqlQuery.dcql_query

      const credentialQueryMap = new Map<string, string>(
        dcql_query.credentials.map((c: { id: string; format: string }) => [c.id, c.format])
      )

      const results: Record<string, VpTokenPayload[]> = {}

      for (const [credentialQueryId, vpArray] of Object.entries(response.vp_token)) {
        const format = credentialQueryMap.get(credentialQueryId)
        if (!format) {
          throw err('ILLEGAL_ARGUMENT', {
            message: `Unknown credential query id: ${credentialQueryId}`,
          })
        }

        if (vpArray.length === 0) {
          throw err('INVALID_VP_TOKEN', {
            message: `Credential query '${credentialQueryId}' must have at least one presentation.`,
          })
        }

        const providerKey = format === 'jwt_vc_json' ? 'jwt_vp_json' : format
        const provider = selectProvider(verifiablePresentation$, providerKey)
        if (!provider) {
          throw err('UNSUPPORTED_VP_TOKEN', {
            message: `VP format '${format}' is not supported.`,
          })
        }

        // Limitations (not yet supported):
        //   - claim_sets: represents OR conditions between alternative claim sets; when present,
        //     requiredClaimKeys cannot express the OR logic and DCQL-level validation
        //   - null / number path elements: act as wildcards or array indices and cannot be
        //     mapped to a specific dot-notation key, so they are not handled here.
        const credentialQuery = dcql_query.credentials.find(
          (c: { id: string }) => c.id === credentialQueryId
        ) as { claims?: { path: (string | number | null)[] }[]; claim_sets?: unknown[] } | undefined
        const specifiedDisclosures = (credentialQuery?.claims ?? [])
          .filter((c) => c.path.every((k) => typeof k === 'string'))
          .map((c) => (c.path as string[]).join('.'))

        const verifyOptions: VerifyVerifiablePresentationVerifyOptions =
          format === 'dc+sd-jwt'
            ? options?.isKbJwt
              ? {
                  kind: 'dc+sd-jwt',
                  specifiedDisclosures,
                  isKbJwt: true,
                  expectedAud,
                  expectedNonce,
                  expectedTransactionDataHashes: options?.expectedTransactionDataHashes,
                }
              : {
                  kind: 'dc+sd-jwt',
                  specifiedDisclosures,
                  expectedAud,
                  expectedNonce,
                  expectedTransactionDataHashes: options?.expectedTransactionDataHashes,
                }
            : { kind: 'jwt_vp_json', expectedAud, expectedNonce }

        const payloads: VpTokenPayload[] = []
        for (const vp of vpArray) {
          if (typeof vp !== 'string') {
            throw err('UNSUPPORTED_VP_TOKEN', {
              message: 'Non-string VP format is not supported.',
            })
          }
          payloads.push(await provider.verify(vp, verifyOptions))
        }
        results[credentialQueryId] = payloads
      }

      const presentedIds = new Set(Object.keys(results))
      const credentialSets = dcql_query.credential_sets

      if (!credentialSets) {
        for (const cred of dcql_query.credentials) {
          if (!presentedIds.has(cred.id)) {
            throw err('INVALID_VP_TOKEN', {
              message: `Required credential query '${cred.id}' was not included in the presentation.`,
            })
          }
        }
      } else {
        for (const set of credentialSets) {
          if (set.required === false) continue
          const satisfied = set.options.some((option: string[]) =>
            option.every((id: string) => presentedIds.has(id))
          )
          if (!satisfied) {
            throw err('INVALID_VP_TOKEN', {
              message: `No option of a required credential_set was fully presented. Options: ${JSON.stringify(set.options)}`,
            })
          }
        }
      }

      if (expectedNonce) {
        const nonceValid = await nonceStore$.validate(Cnonce(expectedNonce))
        if (!nonceValid) {
          throw err('INVALID_NONCE', {
            message: 'nonce is not valid.',
          })
        }
        await nonceStore$.revoke(Cnonce(expectedNonce))
      }

      await transactionDataStore$.delete(TransactionId(transactionId))

      return results
    },
  }
}

export { VerifierMetadata } from './verifier-metadata.types'
export { ClientId as VerifierClientId } from './client-id.types'
export { AuthorizationResponse as VerifierAuthorizationResponse } from './authorization-response.types'
export { ClientIdScheme as VerifierClientIdScheme } from './client-id-scheme.types'
export { RequestObjectId as VerifierRequestObjectId } from './request-object-id.types'
export { PresentationExchange } from './presentation-exchange.types'
export { Dcql } from './dcql.type'
export { ClientIdentifier } from './client-id-scheme.types'
