import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialIssuerMetadata,
} from '../src/credential-issuer.types'

describe('credential-issuer.type', () => {
  describe('CredentialIssuer', () => {
    it('should accept a valid issuer URL', () => {
      const actual = CredentialIssuer('https://issuer.example.com')

      assert.equal(actual, 'https://issuer.example.com')
    })

    it('should reject an invalid issuer URL', () => {
      assert.throws(() => CredentialIssuer('not-a-url'))
    })
  })

  describe('CredentialConfigurationId', () => {
    it('should accept a valid string', () => {
      const actual = CredentialConfigurationId('university_degree')

      assert.equal(actual, 'university_degree')
    })
  })

  describe('CredentialIssuerMetadata', () => {
    const baseInput = {
      credential_issuer: 'https://issuer.example.com',
      credential_endpoint: 'https://issuer.example.com/credential',
      credential_configurations_supported: {
        university_degree: {
          format: 'jwt_vc_json',
          credential_definition: {
            type: ['VerifiableCredential', 'UniversityDegreeCredential'],
          },
        },
      },
    }

    it('should accept valid minimal metadata', () => {
      const actual = CredentialIssuerMetadata(baseInput)

      assert.equal(actual.credential_endpoint, 'https://issuer.example.com/credential')
    })

    it('should accept https batch and deferred endpoints', () => {
      const actual = CredentialIssuerMetadata({
        ...baseInput,
        batch_credential_endpoint: 'https://issuer.example.com/batch_credential',
        deferred_credential_endpoint: 'https://issuer.example.com/deferred_credential',
      })

      assert.equal(actual.batch_credential_endpoint, 'https://issuer.example.com/batch_credential')
      assert.equal(
        actual.deferred_credential_endpoint,
        'https://issuer.example.com/deferred_credential'
      )
    })

    it('should reject http credential_endpoint', () => {
      // Detailed URL scheme validation cases are covered in endpoint-url.validator tests.
      assert.throws(() =>
        CredentialIssuerMetadata({
          ...baseInput,
          credential_endpoint: 'http://issuer.example.com/credential',
        })
      )
    })

    it('should reject malformed credential_endpoint', () => {
      assert.throws(() =>
        CredentialIssuerMetadata({
          ...baseInput,
          credential_endpoint: ':::invalid:::',
        })
      )
    })

    it('should reject when credential_configurations_supported is missing', () => {
      assert.throws(() =>
        CredentialIssuerMetadata({
          credential_issuer: 'https://issuer.example.com',
          credential_endpoint: 'https://issuer.example.com/credential',
        })
      )
    })

    it('should reject empty credential_definition.type', () => {
      assert.throws(() =>
        CredentialIssuerMetadata({
          ...baseInput,
          credential_configurations_supported: {
            invalid_config: {
              format: 'jwt_vc_json',
              credential_definition: {
                type: [],
              },
            },
          },
        })
      )
    })

    it('should accept valid hex color values in display', () => {
      const actual = CredentialIssuerMetadata({
        ...baseInput,
        display: [
          {
            name: 'Example Issuer',
            background_color: '#112233',
            text_color: '#ffffff',
          },
        ],
      })

      assert.equal(actual.display?.[0]?.background_color, '#112233')
      assert.equal(actual.display?.[0]?.text_color, '#ffffff')
    })

    it('should reject invalid hex color values in display', () => {
      assert.throws(() =>
        CredentialIssuerMetadata({
          ...baseInput,
          display: [
            {
              name: 'Example Issuer',
              background_color: 'red',
            },
          ],
        })
      )
    })
  })
})
