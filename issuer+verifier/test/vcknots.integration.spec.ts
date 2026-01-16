import assert from 'node:assert/strict'
import { before, describe, it, mock } from 'node:test'
import type { JWK } from 'jose'
import { SignJWT } from 'jose/jwt/sign'
import { importJWK } from 'jose/key/import'
import {
  AuthorizationResponse,
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
  ClientId,
  VerifierMetadata,
} from '../src'
import { CredentialConfigurationId, CredentialIssuerMetadata } from '../src/credential-issuer.types'
import { PreAuthorizedCode } from '../src/pre-authorized-code.types'
import { GrantType, TokenRequest, TokenResponse } from '../src/token-request.types'
import { Vcknots, vcknots } from '../src/vcknots'

type JwtHeader = {
  alg: 'ES256'
  typ?: 'JWT'
  kid?: string
}
type JwtPayload = {
  [key: string]: unknown
}
async function createJwt(nonce: string): Promise<string> {
  const privateJwk: JWK = {
    kty: 'EC',
    crv: 'P-256',
    x: 'ezZgKwMueAyZLHUgSpzNkbOWDgjJXTAOJn8MftOnayQ',
    y: 'Fy_U4KyZQf-9jKpFJtH6OFFRXmwAcveyfuoDp1hSOFo',
    d: 'jAfOh_53IRxqpEsFojZK8iHP--L8ol3ePEo3DnwiIyM',
  }
  const privateKey = await importJWK(privateJwk, 'ES256')

  const header: JwtHeader = {
    alg: 'ES256',
    typ: 'JWT',
    kid: 'did:key:zDnaeYiwHNeMYaj21Wo9jPCowtnBrY8he8UCK8ZZN1mhhx8PM',
  }

  const payload: JwtPayload = {
    iss: 'did:key:zDnaeYiwHNeMYaj21Wo9jPCowtnBrY8he8UCK8ZZN1mhhx8PM',
    vp: {
      type: ['VerifiablePresentation'],
      verifiableCredential: [
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6Imh0dHBzOi8vbWVkYWxib29rLWRldi1hcHAtaXNzdWVyLndlYi5hcHAvY3JlZGVudGlhbHMvS2M0MFpmWnR0VUpWZFFrNFNIbnYiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiTWVkYWxCb29rTWVkYWwiLCJNREI0MDQyYzNlMjViOTQ0NWE0ODhmMDlhODM4YTM0ODU4NyJdLCJpc3N1ZXIiOiJodHRwczovL21lZGFsYm9vay1kZXYtYXBwLWlzc3Vlci53ZWIuYXBwL2lzc3VlcnMvWW9leTlIRmpUWVB5Y21kcXdaVVMiLCJpc3N1YW5jZURhdGUiOiIyMDI0LTEyLTI0VDAxOjM4OjQzLjYzMloiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSIsIm1lZGFsaXN0T2YiOnsibmFtZSI6W3sidmFsdWUiOiJ3b25kZXJsYW5kIiwibG9jYWxlIjoiamEtSlAifV0sImRlc2NyaXB0aW9uIjpbeyJ2YWx1ZSI6IndvbmRlcmxhbmQiLCJsb2NhbGUiOiJqYS1KUCJ9XSwibG9nbyI6W3sidmFsdWUiOnsidXJpIjoiaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL21lZGFsYm9vay1kZXYuYXBwc3BvdC5jb20vaXNzdWVyJTJGdjElMkZpc3N1ZXJzJTJGWW9leTlIRmpUWVB5Y21kcXdaVVMlMkZjcmVkZW50aWFscyUyRkJwdGtXdW1HQUQyMXpTNnVSbTJhLnBuZyJ9LCJsb2NhbGUiOiJqYS1KUCJ9XX19fSwiaXNzIjoiaHR0cHM6Ly9tZWRhbGJvb2stZGV2LWFwcC1pc3N1ZXIud2ViLmFwcC9pc3N1ZXJzL1lvZXk5SEZqVFlQeWNtZHF3WlVTIiwibmJmIjoxNzM1MDA0MzIzNjMyLCJzdWIiOiJkaWQ6a2V5OnpEbmFlWWl3SE5lTVlhajIxV285alBDb3d0bkJyWThoZThVQ0s4WlpOMW1oaHg4UE0ifQ._We9A2jRgGukc892zWTZq-ASrpP3wYxxW8S8_7pOvjBWYm5PkU9RXhQf6JisLlOOSa5QZ_rA4lf4E7t6nloEhw',
      ],
      holder: 'did:key:zDnaeYiwHNeMYaj21Wo9jPCowtnBrY8he8UCK8ZZN1mhhx8PM',
    },
    nonce: nonce,
  }

  const jwt = await new SignJWT(payload).setProtectedHeader(header).sign(privateKey)

  return jwt
}

describe('Vcknots', () => {
  let vk: Vcknots

  const issuerMetadata = CredentialIssuerMetadata({
    credential_issuer: 'https://example.com/issuer/1',
    credential_endpoint: 'https://example.com/issuer/1/offer',
    authorization_servers: ['https://example.com/authz'],
    batch_credential_endpoint: 'https://example.com/issuer-full/batch_credential',
    deferred_credential_endpoint: 'https://example.com/issuer-full/deferred_credential',
    credential_response_encryption_alg_values_supported: ['ECDH-ES+A256KW'],
    credential_response_encryption_enc_values_supported: ['A256GCM'],
    require_credential_response_encryption: true,
    credential_configurations_supported: {
      EmployeeID_jwt_vc_json: {
        format: 'jwt_vc_json',
        scope: 'employee_id',
        cryptographic_binding_methods_supported: ['did:example'],
        cryptographic_suites_supported: ['ES256K'],
        credential_definition: {
          type: ['VerifiableCredential', 'EmployeeIDCredential'],
          credentialSubject: {
            employee_id: { mandatory: true, value_type: 'string' },
            given_name: {
              display: [{ name: 'Given Name', locale: 'en-US' }],
            },
          },
        },
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ['ES256'],
          },
        },
        credential_signing_alg_values_supported: ['ES256'],
        display: [
          {
            name: 'Employee ID',
            locale: 'en-US',
            logo: {
              uri: 'https://example.com/logo.png',
              alt_text: 'Employee ID Logo',
            },
            description: 'Digital Employee ID Card',
            background_color: '#0000FF',
            text_color: '#FFFFFF',
          },
        ],
      },
    },
  })

  const authzIssuer = AuthorizationServerIssuer('https://example.com/issuer')
  const authzMetadata = AuthorizationServerMetadata({
    issuer: 'https://example.com/issuer',
    authorization_endpoint: 'https://example.com/auth',
    token_endpoint: 'https://example.com/token',
    response_types_supported: ['code'],
  })

  before(async () => {
    vk = vcknots()
    // First, create issuerMetadata and authorizationServerMetadata
    const existingIssuer = await vk.issuer.findIssuerMetadata(issuerMetadata.credential_issuer)
    if (!existingIssuer) {
      await vk.issuer.createIssuerMetadata(issuerMetadata)
    }

    const existingAuthz = await vk.authz.findAuthzServerMetadata(authzIssuer)
    if (!existingAuthz) {
      await vk.authz.createAuthzServerMetadata(authzMetadata)
    }
  })

  describe('issuer', () => {
    it('should save and find issuer metadata', async () => {
      // Since the metadata is already created, test only the metadata retrieval process
      const found = await vk.issuer.findIssuerMetadata(issuerMetadata.credential_issuer)

      assert.ok(found)
      assert.deepEqual(found, issuerMetadata)
    })

    it('should throw DUPLICATE_ISSUER when creating duplicate issuer metadata', async () => {
      // Since it has already been created in the before hook, a duplicate error should occur
      await assert.rejects(vk.issuer.createIssuerMetadata(issuerMetadata), {
        name: 'DUPLICATE_ISSUER',
        message: `issuer ${issuerMetadata.credential_issuer} is already registered.`,
      })
    })

    it('should create credential offer with pre authorized code', async () => {
      const configurations = [CredentialConfigurationId('EmployeeID_jwt_vc_json')]
      const offer = await vk.issuer.offerCredential(
        issuerMetadata.credential_issuer,
        configurations,
        {
          usePreAuth: true,
          txCode: {
            inputMode: 'numeric',
            length: 4,
            description: 'PIN',
          },
        }
      )

      assert.ok(offer)
      assert.equal(offer.credential_issuer, issuerMetadata.credential_issuer)
      assert.deepEqual(offer.credential_configuration_ids, configurations)
      assert.ok(offer.grants)
      assert.ok(offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'])
      const pre = offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']
      assert.ok(pre['pre-authorized_code'])
      assert.equal(pre.tx_code?.input_mode, 'numeric')
      assert.equal(pre.tx_code?.length, 4)
      assert.equal(pre.tx_code?.description, 'PIN')
    })
    it('should create access token when grant_type is urn:ietf:params:oauth:grant-type:pre-authorized_code', async () => {
      // Since the authzIssuer has already been created, remove the creation step
      const configurations = [CredentialConfigurationId('EmployeeID_jwt_vc_json')]
      const offer = await vk.issuer.offerCredential(
        issuerMetadata.credential_issuer,
        configurations,
        {
          usePreAuth: true,
          txCode: {
            inputMode: 'numeric',
            length: 4,
            description: 'PIN',
          },
        }
      )

      assert.ok(offer.grants)
      const grant = offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']
      assert.ok(grant)
      const code = grant?.['pre-authorized_code']
      assert.ok(code)

      const tokenRequest: TokenRequest = {
        grant_type: GrantType.PreAuthorizedCode,
        'pre-authorized_code': PreAuthorizedCode(code),
      }

      const accessToken = await vk.authz.createAccessToken(authzIssuer, tokenRequest, {
        ttlSec: 3600,
        c_nonce_expire_in: 300000,
      })

      const tokenResponse = accessToken as TokenResponse

      assert.ok(tokenResponse)
      assert.ok(typeof tokenResponse.access_token === 'string')
      assert.equal(tokenResponse.token_type, 'bearer')
      assert.ok(typeof tokenResponse.expires_in === 'number' && tokenResponse.expires_in > 0)
      assert.ok(typeof tokenResponse.c_nonce === 'string')
      assert.ok(typeof tokenResponse.c_nonce_expires_in === 'number')
      assert.ok(
        typeof tokenResponse.c_nonce_expires_in === 'number' && tokenResponse.c_nonce_expires_in > 0
      )
    })
  })

  describe('authz', () => {
    it('should save and find authorization server metadata', async () => {
      // Since the metadata is already created, test only the metadata retrieval process
      const found = await vk.authz.findAuthzServerMetadata(authzIssuer)

      assert.ok(found)
      assert.equal(found.issuer, authzIssuer)
      assert.deepEqual(found, authzMetadata)
    })

    it('should throw DUPLICATE_AUTHZ_SERVER when creating duplicate authz server metadata', async () => {
      // Since it has already been created in the before hook, a duplicate error should occur
      await assert.rejects(vk.authz.createAuthzServerMetadata(authzMetadata), {
        name: 'DUPLICATE_AUTHZ_SERVER',
        message: `issuer ${authzIssuer} is already registered.`,
      })
    })
  })

  describe('verifier', () => {
    const verifierId = ClientId('https://example.com/verifier')
    const metadata = VerifierMetadata({
      client_name: 'Test Verifier',
      vp_formats: {
        jwt_vc_json: {
          alg: ['ES256'],
        },
        jwt_vp_json: {
          alg: ['ES256'],
        },
        ldp_vp: {
          proof_type: ['JsonWebSignature2020'],
        },
        'dc+sd-jwt': {
          'sd-jwt_alg_values': ['ES256', 'ES384'],
          'kb-jwt_alg_values': ['ES256', 'ES384'],
        },
      },
    })
    const presentationDefinition = {
      id: 'test-pd-id',
      input_descriptors: [
        {
          id: 'test_credential',
          constraints: {
            fields: [
              {
                path: ['$.type[*]'],
                filter: {
                  type: 'string',
                  const: 'TestCredential',
                },
              },
            ],
          },
        },
      ],
    }
    const dcqlQuery = {
      credentials: [
        {
          id: 'my_credential',
          format: 'dc+sd-jwt',
          meta: {
            vct_values: ['https://credentials.example.com/identity_credential'],
          },
          claims: [
            { path: ['last_name'] },
            { path: ['first_name'] },
            { path: ['address', 'street_address'] },
          ],
        },
      ],
    }

    before(async () => {
      await vk.verifier.createVerifierMetadata(verifierId, metadata)
    })

    it('should throw DUPLICATE_VERIFIER when creating duplicate verifier metadata', async () => {
      // Since it has already been created in the before hook, a duplicate error should occur
      await assert.rejects(vk.verifier.createVerifierMetadata(verifierId, metadata), {
        name: 'DUPLICATE_VERIFIER',
        message: `verifier ${verifierId} is already registered.`,
      })
    })

    it('should create authorization request with presentation exchange', async () => {
      const authzRequest = await vk.verifier.createAuthzRequest(
        verifierId,
        'vp_token',
        `redirect_uri:${verifierId}`,
        'direct_post',
        {
          presentation_definition: presentationDefinition,
        },
        false,
        {}
      )

      assert.ok(authzRequest)
      assert.equal(authzRequest.client_id, `redirect_uri:${verifierId}`)
      assert.equal(authzRequest.response_type, 'vp_token')
      assert.equal(authzRequest.response_mode, 'direct_post')
      assert.equal(authzRequest.client_metadata?.client_name, metadata.client_name)
      assert.deepEqual(authzRequest.client_metadata?.vp_formats, metadata.vp_formats)
      assert.ok(authzRequest.client_metadata.jwks)
      assert.ok(authzRequest.client_metadata.jwks.keys)
      assert.ok(authzRequest.nonce)
      assert.ok('presentation_definition' in authzRequest && authzRequest.presentation_definition)
      assert.deepEqual(authzRequest.presentation_definition, presentationDefinition)
    })

    it('should create authorization request with dcql', async () => {
      const authzRequest = await vk.verifier.createAuthzRequest(
        verifierId,
        'vp_token',
        `redirect_uri:${verifierId}`,
        'direct_post',
        {
          dcql_query: dcqlQuery,
        },
        false,
        {}
      )

      assert.ok(authzRequest)
      assert.equal(authzRequest.client_id, `redirect_uri:${verifierId}`)
      assert.equal(authzRequest.response_type, 'vp_token')
      assert.equal(authzRequest.response_mode, 'direct_post')
      assert.equal(authzRequest.client_metadata?.client_name, metadata.client_name)
      assert.deepEqual(authzRequest.client_metadata?.vp_formats, metadata.vp_formats)
      assert.ok(authzRequest.client_metadata.jwks)
      assert.ok(authzRequest.client_metadata.jwks.keys)
      assert.ok(authzRequest.nonce)
      assert.ok('dcql_query' in authzRequest && authzRequest.dcql_query)
      assert.deepEqual(authzRequest.dcql_query, dcqlQuery)
    })

    it('should create authorization request with request_uri', async () => {
      const authzRequest = await vk.verifier.createAuthzRequest(
        verifierId,
        'vp_token',
        `redirect_uri:${verifierId}`,
        'direct_post',
        {
          presentation_definition: presentationDefinition,
        },
        true,
        { base_url: 'https://example.com' }
      )

      assert.ok(authzRequest)
      assert.equal(authzRequest.client_id, `redirect_uri:${verifierId}`)
      assert.ok(authzRequest.request_uri)
    })

    it('should verify presentations', async () => {
      const authzRequest = await vk.verifier.createAuthzRequest(
        verifierId,
        'vp_token',
        `redirect_uri:${verifierId}`,
        'direct_post',
        {
          presentation_definition: presentationDefinition,
        },
        false,
        {}
      )
      const nonce = authzRequest.nonce
      if (typeof nonce !== 'string') {
        assert.fail('nonce must be a string')
      }
      const vpJwt = await createJwt(nonce)

      const response: AuthorizationResponse = AuthorizationResponse({
        presentation_submission: {
          id: '1',
          definition_id: presentationDefinition.id,
          descriptor_map: [
            {
              id: '2',
              format: 'jwt_vp_json',
              path: '$.vp',
              path_nested: {
                id: '2',
                format: 'jwt_vc_json',
                path: '$.verifiableCredential[0]',
              },
            },
          ],
        },
        vp_token: vpJwt,
      })

      mock.method(globalThis, 'fetch', async () => {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            issuer: 'https://medalbook-dev-app-issuer.web.app/issuers/Yoey9HFjTYPycmdqwZUS',
            jwks: {
              keys: [
                {
                  kid: 'https://medalbook-dev-app-issuer.web.app/issuers/Yoey9HFjTYPycmdqwZUS',
                  kty: 'EC',
                  x: 'eo0GxuF-PxTAx1xO8VFQ1R8e04Tx7wqFHFP_700KkAY',
                  y: 'wp_SksU1y_2lNlaSn04L4UN5tu3zdI1fQL-IfV2gjfs',
                  crv: 'P-256',
                },
              ],
            },
          }),
        }
      })

      await vk.verifier.verifyPresentations(verifierId, response)

      mock.reset()
    })

    it('should verify presentations (dc+sd-jwt)', async () => {
      const authzRequest = await vk.verifier.createAuthzRequest(
        verifierId,
        'vp_token',
        `redirect_uri:${verifierId}`,
        'direct_post',
        {
          presentation_definition: presentationDefinition,
        },
        false,
        {}
      )
      const nonce = authzRequest.nonce
      if (typeof nonce !== 'string') {
        assert.fail('nonce must be a string')
      }
      const sampleDcSdJwtVp =
        'eyJhbGciOiJFUzI1NiIsImtpZCI6Ik9GWV9kbVpuQnIxMUYxSkg5dzdNMUVPNEEweGU4VmpQQUl6YS02QzdfVUUiLCJ0eXBlIjoiZGMrc2Qtand0In0.eyJpc3MiOiJodHRwczovL3Zja25vdHMtYXBwLXNkLWp3dC0tdmNrbm90cy5hc2lhLWVhc3QxLmhvc3RlZC5hcHAiLCJpYXQiOjE3NjU1MjI1MDQsInZjdCI6InVybjpldWRpOnBpZDoxIiwiZXhwIjoxODgzMDAwMDAwLCJfc2QiOlsiMVBJdkhhVnM1SmN5V1h0QWNTakNFVUF3T1Radi1WZll3NV9vaUNBTHpkSSIsIkRNa2ZkWVIwOHVrX2kxSkx5Qzd4MmtaM2ZqXzNUdVdNM2huQ0tmQURiT0UiLCJGUlJWU3FnMXlLM1JObjhmS1VjaU1vV3ZQb25TdnhnMGV4MFhRcTRVa1VrIiwiWlhTTS1VRkRRVzZ1T00xalhFdkwyYld4RkxaenJyMlBHdHhkeWg4SVZNcyIsIm1HVWFxdWNaQlB5QzZBV0twS3NreDJTNXNWSzJpSTE5eS1kWHo3ODNnaFUiLCJ3c1JLY2RqanJ3ZnRtenU4R1V6THREdUtkZzNsSElZTmc5SnIwVEdiMENzIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.HkshPJyBeptaVKSyoWl6-n1SeZ2-ZaHn_H4LUbj33pXCY-4aWwv2otXlUfOBp93QH8rXbNW_ZaJ1e1oij1pN1g~WyIzTHJnYjRMWmtzTjlwYVBQNGhfYWJRIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJyQ0NYZjRNSW5rakVTUGhqaEZ0alFRIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyJab1k2ZGdIUXVlRmFheE85REFDenpnIiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJsZjVYaEVObzZHNlZHdkZnSEdLNlJnIiwicGhvbmVfbnVtYmVyIiwiKzEtMjAyLTU1NS0wMTAxIl0~WyJGNjJoVlZnSEFQMXVOZ2pCVlNPd2RnIiwiYWRkcmVzcyIsIntcInN0cmVldF9hZGRyZXNzXCI6IFwiMTIzIE1haW4gU3RcIiwgXCJsb2NhbGl0eVwiOiBcIkFueXRvd25cIiwgXCJyZWdpb25cIjogXCJBbnlzdGF0ZVwiLCBcImNvdW50cnlcIjogXCJVU1wifSJd~WyJTc0VMNC1zTlFDQkprSXI0UXBqaFVRIiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd~'

      const response: AuthorizationResponse = AuthorizationResponse({
        presentation_submission: {
          id: '1',
          definition_id: presentationDefinition.id,
          descriptor_map: [
            {
              id: '2',
              format: 'dc+sd-jwt',
              path: '$',
            },
          ],
        },
        vp_token: sampleDcSdJwtVp,
      })

      mock.method(globalThis, 'fetch', async () => {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            issuer: 'https://vcknots-app-sd-jwt--vcknots.asia-east1.hosted.app',
            jwks: {
              keys: [
                {
                  kty: 'EC',
                  x: 'Mt6vOk6YLHXBNAyJSWOqmZry956UMpHHQayIY4VCEVA',
                  y: 'T7Hg-uiS5g0_J3UpC4An7IOF1IxwaVH3DD3Z5VeEVHw',
                  crv: 'P-256',
                  kid: 'OFY_dmZnBr11F1JH9w7M1EO4A0xe8VjPAIza-6C7_UE',
                  use: 'sig',
                  alg: 'ES256',
                },
              ],
            },
          }),
        }
      })
      await vk.verifier.verifyPresentations(verifierId, response)

      mock.reset()
    })
  })
})
