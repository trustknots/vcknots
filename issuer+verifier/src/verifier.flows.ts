import base64url from 'base64url'
import * as jwt from 'jsonwebtoken'
import { AuthorizationRequest } from './authorization-request.types'
import { AuthorizationResponse } from './authorization-response.types'
import { ClientId } from './client-id.types'
import { VerifiableCredential, parseVerifiableCredentialBase } from './credential.types'
import { Dcql } from './dcql.type'
import { err, raise } from './errors/vcknots.error'
import { PresentationExchange } from './presentation-exchange.types'
import { CredentialQueryGenerationOptions } from './providers'
import { selectProvider } from './providers/provider.utils'
import { RequestObject } from './request-object.types'
import { DeepPartialUnknown } from './type.utils'
import { VcknotsContext } from './vcknots.context'
import { VerifierMetadata } from './verifier-metadata.types'

import { RequestObjectId } from './request-object-id.types'
import { Certificate, JwkTmp } from './signature-key.types'
import { exportJWK, importSPKI } from 'jose'
import { ClientIdentifier } from './client-id-scheme.types'

type CreateVerifierMetadataOptionsBase = {
  format: 'pem' | 'jwk'
  alg: string
  kid?: string
}
type CreateVerifierMetadataOptionsWithCert = CreateVerifierMetadataOptionsBase & {
  privateKey: string | JwkTmp
  certificate: string | string[]
}
type CreateVerifierMetadataOptionsWithPubKey = CreateVerifierMetadataOptionsBase & {
  privateKey: string | JwkTmp
  publicKey: string | JwkTmp
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

export type FindRequestObjectOptions = {
  alg?: string
  // https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.11 is not supported
  // wallet_metadata? :
  // wallet_nonce?: string
}

export type VerifierFlow = {
  //findVerifierMetadata(/* client_id? */): Promise<VerifierMetadata>
  findVerifierCertificate: (id: ClientId) => Promise<Certificate | null>
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
    query: DeepPartialUnknown<PresentationExchange> | DeepPartialUnknown<Dcql>,
    isRequestUri: boolean,
    options: CreateAuthzRequestOptions
  ): Promise<AuthorizationRequest>
  findRequestObject(
    verifierId: ClientId,
    objectId: RequestObjectId,
    options?: FindRequestObjectOptions
  ): Promise<string>
  verifyPresentations: (id: ClientId, response: AuthorizationResponse) => Promise<void>
}

const isPresentationExchange = (query: unknown): query is PresentationExchange =>
  typeof query === 'object' &&
  query !== null &&
  ('presentation_definition' in query || 'presentation_definition_uri' in query)

export const initializeVerifierFlow = (context: VcknotsContext): VerifierFlow => {
  const cnonce$ = context.providers.get('cnonce-provider')
  const nonceStore$ = context.providers.get('cnonce-store-provider')
  const query$ = context.providers.get('credential-query-provider')
  const verifierMetadata$ = context.providers.get('verifier-metadata-store-provider')
  const credential$ = context.providers.get('credential-provider')
  const jwtSignature$ = context.providers.get('jwt-signature-provider')
  const holderBinding$ = context.providers.get('holder-binding-provider')
  const did$ = context.providers.get('did-provider')
  const key$ = context.providers.get('verifier-signature-key-provider')
  const keyStore$ = context.providers.get('verifier-signature-key-store-provider')
  const requestObjectId$ = context.providers.get('request-object-id-provider')
  const requestObjectStore$ = context.providers.get('request-object-store-provider')
  const authzRequestJAR$ = context.providers.get('authz-request-jar-provider')
  const certificateStore$ = context.providers.get('verifier-certificate-store-provider')
  const certificate$ = context.providers.get('certificate-provider')
  const transactionData$ = context.providers.get('transaction-data-provider')

  return {
    async findVerifierCertificate(id) {
      return certificateStore$.fetch(id)
    },
    async createVerifierMetadata(verifierId, metadata, options) {
      const current = await verifierMetadata$.fetch(verifierId)
      if (current) {
        throw err('DUPLICATE_VERIFIER', {
          message: `verifier ${verifierId} is already registered.`,
        })
      }
      const verifierMetadata = metadata
      if (!options) {
        // create new key pair (not support x509)
        const alg = metadata.authorization_signed_response_alg ?? 'ES256'
        const provider = selectProvider(key$, alg)
        const keyPairs = await provider.generate()
        // support key Pairs format jwk
        keyStore$.save(verifierId, [{ ...keyPairs, format: 'jwk', declaredAlg: alg }])
        verifierMetadata.jwks = { keys: [keyPairs.publicKey] }
        verifierMetadata.authorization_signed_response_alg = alg
      } else if ('publicKey' in options && options.publicKey !== undefined) {
        // use provided key pair (not support x509)
        if (!options.alg) {
          throw err('INTERNAL_SERVER_ERROR', {
            message: 'alg is required in the provided publicKey.',
          })
        }
        keyStore$.save(verifierId, [
          {
            format: options.format,
            declaredAlg: options.alg,
            kid: options.kid,
            publicKey: options.publicKey,
            privateKey: options.privateKey,
          },
        ])
        if (options.format === 'jwk' && typeof options.publicKey !== 'string') {
          verifierMetadata.jwks = { keys: [options.publicKey] }
          verifierMetadata.authorization_signed_response_alg = options.alg
        } else if (options.format === 'pem' && typeof options.publicKey === 'string') {
          const key = await importSPKI(options.publicKey, options.alg)
          const jwk = await exportJWK(key)
          verifierMetadata.jwks = { keys: [{ ...jwk }] }
          verifierMetadata.authorization_signed_response_alg = options.alg
        }
      } else if ('certificate' in options && options.certificate !== undefined) {
        // use provided key pair and x509 certificate
        // password protected private key is not supported
        if (!options.alg) {
          throw err('INTERNAL_SERVER_ERROR', {
            message: 'alg is required in the provided privateKey.',
          })
        }
        if (typeof options.certificate === 'string') {
          options.certificate = [options.certificate]
        }
        const certificates = Certificate(options.certificate)
        const certValid = await certificate$.validate(certificates)
        if (!certValid) {
          throw err('INVALID_CERTIFICATE', {
            message: 'The provided certificate is not valid.',
          })
        }
        certificateStore$.save(verifierId, certificates)
        const certificate = certificates[0]
        const publicKey = await certificate$.getPublicKey(certificate)
        keyStore$.save(verifierId, [
          {
            format: options.format,
            declaredAlg: options.alg,
            kid: options.kid,
            publicKey: publicKey,
            privateKey: options.privateKey,
          },
        ])
        const key = await importSPKI(publicKey, options.alg)
        const jwk = await exportJWK(key)
        verifierMetadata.jwks = { keys: [{ ...jwk }] }
        verifierMetadata.authorization_signed_response_alg = options.alg
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
      const authzRequestJAR = selectProvider(authzRequestJAR$, client_id_scheme)
      if (!authzRequestJAR) {
        throw err('UNSUPPORTED_CLIENT_ID_SCHEME', {
          message: 'client_id_scheme is not supported.',
        })
      }
      if (client_id_scheme === 'x509_san_dns' || client_id_scheme === 'x509_san_uri') {
        const certificate = await certificateStore$.fetch(verifierId)
        if (!certificate) {
          throw err('CERTIFICATE_NOT_FOUND', {
            message: 'verifier certificate is not found.',
          })
        }
      }

      const metadata = (await verifierMetadata$.fetch(verifierId)) ?? raise('VERIFIER_NOT_FOUND')

      const args: CredentialQueryGenerationOptions = isPresentationExchange(query)
        ? {
            kind: 'presentation-exchange',
            query: query as PresentationExchange,
          }
        : { kind: 'dcql', query: query as Dcql }

      const parsedQuery = await selectProvider(query$, args.kind).generate(args)

      const transaction_data: string[] = []
      const credentialIds: string[] = []
      let isDcSDJwtRequested = false
      // Validate: Metadata supports format
      const vpFormats = Object.keys(metadata.vp_formats)
      if (isPresentationExchange(parsedQuery)) {
        if (parsedQuery.presentation_definition) {
          const input_descriptors = parsedQuery.presentation_definition.input_descriptors
          if (input_descriptors) {
            for (const descriptor of input_descriptors) {
              if (descriptor.format) {
                for (const format of Object.keys(descriptor.format)) {
                  if (!vpFormats.includes(format)) {
                    throw err('VERIFIER_VP_FORMATS_NOT_SUPPORTED', {
                      message: `The vp_format ${format} is not supported by the verifier.`,
                    })
                  }
                  if (format === 'dc+sd-jwt') {
                    credentialIds.push(descriptor.id)
                    isDcSDJwtRequested = true
                  }
                }
              }
            }
            if (isDcSDJwtRequested && options.transaction_data) {
              transaction_data.push(
                transactionData$.generate(options.transaction_data.type, credentialIds)
              )
            }
          }
        }
      } else if (parsedQuery.dcql_query) {
        const credentials = parsedQuery.dcql_query.credentials
        console.log('credentials:', credentials)
        if (credentials) {
          for (const credential of credentials) {
            if (credential.format) {
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
          }
          if (isDcSDJwtRequested && options.transaction_data) {
            transaction_data.push(
              transactionData$.generate(options.transaction_data.type, credentialIds)
            )
          }
        }
      }

      const responseUri = options.response_uri ?? `${verifierId}/post`

      // when using request_uri
      if (isRequestUri ?? true) {
        if (!options.base_url) {
          throw err('INVALID_REQUEST', {
            message: 'base_url is required when is_request_uri is true',
          })
        }
        // create RequestObjectId
        const requestObjectId = await requestObjectId$.generate()

        // create RequestObjectを作成(generate iat and nonce when creating the JAR)
        const requestObject = RequestObject({
          response_type: response_type,
          client_id: client_id,
          scope: options.scope,
          state: options.state,
          response_uri: responseUri,
          iss: verifierId,
          aud: 'https://self-issued.me/v2',
          client_metadata: metadata,
          response_mode: response_mode || 'direct_post',
          ...parsedQuery,
          ...(transaction_data.length > 0 ? { transaction_data } : {}),
        })
        await requestObjectStore$.save(requestObjectId, requestObject)

        return AuthorizationRequest({
          client_id: client_id,
          request_uri: options.request_uri
            ? `${options.request_uri}/${encodeURIComponent(requestObjectId)}`
            : `${options.base_url}/request.jwt/${encodeURIComponent(requestObjectId)}`,
        })
      }

      const nonce = await cnonce$.generate()
      await nonceStore$.save(nonce)
      return AuthorizationRequest({
        client_id: client_id,
        response_uri: responseUri,
        response_type: response_type,
        response_mode: response_mode || 'direct_post',
        client_id_scheme: client_id_scheme,
        client_metadata: metadata,
        nonce,
        ...parsedQuery,
        ...(transaction_data.length > 0 ? { transaction_data } : {}),
      })
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

      const nonce = await cnonce$.generate()
      await nonceStore$.save(nonce)

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
        nonce,
        walletNonce
      )

      const keyProvider = selectProvider(key$, keyAlg)
      if (!keyProvider) {
        throw raise('AUTHZ_VERIFIER_KEY_NOT_FOUND', {
          message: `Verifier signature key provider for ${keyAlg} is not found.`,
        })
      }
      const signature = await keyProvider.sign(verifierId, keyAlg, payload, header)
      if (!signature) {
        throw err('INTERNAL_SERVER_ERROR', {
          message: 'Failed to sign the request object.',
        })
      }

      await requestObjectStore$.delete(objectId)

      const encode = (x: unknown) => base64url.encode(JSON.stringify(x))

      return `${encode(header)}.${encode(payload)}.${signature}`
    },
    async verifyPresentations(id, response) {
      const verifier = await verifierMetadata$.fetch(id)
      if (!verifier) {
        throw raise('VERIFIER_NOT_FOUND', {
          message: 'verifier is not found.',
        })
      }

      const vpToken = Array.isArray(response.vp_token) ? response.vp_token : [response.vp_token]

      if (!Array.isArray(vpToken) || vpToken.length !== 1) {
        throw err('UNSUPPORTED_VP_TOKEN', {
          message: 'Submitting multiple verifiable presentations are not supported yet',
        })
      }
      if (typeof vpToken[0] !== 'string') {
        throw err('UNSUPPORTED_VP_TOKEN', {
          message: 'Bare object vp_token is not supported yet',
        })
      }

      // TODO: review where the processing is located
      const credentials: [
        VerifiableCredential,
        string /* jwt_vc（It is originally the role of the Provider）*/,
      ][] = []
      const decodedVps = []
      for (const token of vpToken) {
        if (typeof token === 'string') {
          const decoded = jwt.decode(token, { complete: true })
          if (!decoded) {
            throw err('INVALID_VP_TOKEN', {
              message: `Invalid vp_token: ${vpToken}`,
            })
          }
          decodedVps.push(decoded)
          const payload =
            typeof decoded.payload === 'string' ? JSON.parse(decoded.payload) : decoded.payload

          const nonce = payload.nonce
          const nonceValid = await nonceStore$.validate(nonce)
          if (!nonceValid) {
            throw err('INVALID_NONCE', {
              message: 'nonce is not valid.',
            })
          }
          await nonceStore$.revoke(nonce)

          const vc = payload.vp.verifiableCredential
          if (Array.isArray(vc)) {
            for (const token of vc) {
              if (typeof token === 'string') {
                const parts = token.split('.')
                const payload = parts[1]
                const decoded = JSON.parse(base64url.decode(payload))
                const credential = decoded.vc ? decoded.vc : decoded
                if (parseVerifiableCredentialBase(credential)) {
                  credentials.push([credential, token])
                }
              } else {
                throw err('ILLEGAL_ARGUMENT', {
                  message: 'VC represented as object is not supported.',
                })
              }
            }
          }
        } else if (typeof token === 'object' && token !== null) {
          throw err('UNSUPPORTED_VP_TOKEN', {
            message: 'Bare object vp_token is not supported yet',
          })
        }
      }
      if (!Array.isArray(credentials) || credentials.length === 0) {
        throw err('INVALID_CREDENTIAL', {
          message: 'No credentials is included',
        })
      }

      const [credential, token] = credentials[0]
      const issuer = credential.issuer
      const vcValid = await credential$.verify(token, issuer, response.presentation_submission)
      if (!vcValid) {
        throw err('INVALID_CREDENTIAL', {
          message: 'credential is not valid.',
        })
      }

      const decoded = decodedVps[0]
      if (!decoded.header.kid) {
        throw err('INVALID_VP_TOKEN', {
          message: `Missing key id in the header: ${JSON.stringify(decoded.header)}`,
        })
      }
      const kid = decoded.header.kid
      const didSplit = kid.split(':')
      if (didSplit.length < 3 || didSplit[0] !== 'did') {
        throw raise('INVALID_PROOF', {
          message: `Invalid DID format: ${kid}`,
        })
      }
      const didDoc = await selectProvider(did$, didSplit[1]).resolveDid(kid)
      if (!didDoc || !didDoc.verificationMethod) {
        throw err('INVALID_VP_TOKEN', {
          message: `Cannot resolve DID: ${decoded.header.kid}`,
        })
      }
      if (!didDoc.id.startsWith('did:key:')) {
        throw err('INVALID_VP_TOKEN', {
          message: `Unsupported DID method: ${didDoc.id}`,
        })
      }

      const vm = didDoc.verificationMethod.find(
        // FIXME: this is a hacky way to find the verification method and only works for did:key
        (it) => it.id.startsWith(`${decoded.header.kid}`)
      )
      if (!vm || !vm.publicKeyJwk) {
        throw err('INVALID_VP_TOKEN', {
          message: `Cannot find verification method: ${decoded.header.kid}`,
        })
      }
      const publicKey = vm.publicKeyJwk
      const JwtValid = await jwtSignature$.verify(vpToken[0], publicKey)
      if (!JwtValid) {
        throw err('INVALID_PROOF', {
          message: 'jwt is not valid.',
        })
      }
      const holderBindingValid = await holderBinding$.verify(
        credentials.map(([it]) => it),
        publicKey
      )
      if (!holderBindingValid) {
        throw err('HOLDER_BINDING_FAILED', {
          message: 'Holder binding verification failed.',
        })
      }
      return
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
