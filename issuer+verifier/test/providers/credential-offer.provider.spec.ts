import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { credentialOffer } from '../../src/providers/credential-offer.provider'
import { CredentialOfferProvider } from '../../src/providers/provider.types'
import {
  CredentialIssuerMetadata,
  CredentialIssuer,
  CredentialConfigurationId,
} from '../../src/credential-issuer.types'
import { PreAuthorizedCode } from '../../src/pre-authorized-code.types'

describe('CredentialOfferProvider', () => {
  const provider: CredentialOfferProvider = credentialOffer()

  const issuer: CredentialIssuerMetadata = {
    credential_issuer: CredentialIssuer('https://issuer.example.com'),
    credential_endpoint: 'https://issuer.example.com/credential',
    credential_configurations_supported: {
      University_Degree: {
        format: 'jwt_vc_json',
        credential_definition: {
          type: ['VCKnots'],
          credentialSubject: {},
        },
        credential_signing_alg_values_supported: ['ES256'],
      },
    },
  }

  const configurations = [
    CredentialConfigurationId('EmployeeID_jwt_vc_json'),
    CredentialConfigurationId('StudentID_ldp_vc'),
  ]

  it('should have correct kind, name, and single properties', () => {
    assert.equal(provider.kind, 'credential-offer-provider')
    assert.equal(provider.name, 'default-credential-offer-provider')
    assert.strictEqual(provider.single, true)
  })

  it('should create a credential offer using pre-authorized code without txCode', async () => {
    const offer = await provider.create(issuer, configurations, {
      usePreAuth: true,
      code: PreAuthorizedCode('pre-auth-code-123'),
    })

    assert.equal(offer.credential_issuer, issuer.credential_issuer)
    assert.deepEqual(offer.credential_configuration_ids, configurations)
    assert.deepEqual(offer.grants, {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': 'pre-auth-code-123',
      },
    })
  })

  it('should create a credential offer using pre-authorized code with txCode', async () => {
    const txCodeInput = {
      inputMode: 'numeric' as const,
      length: 4,
      description: 'PIN',
    }

    const expectedTxCode = {
      input_mode: txCodeInput.inputMode,
      length: txCodeInput.length,
      description: txCodeInput.description,
    }

    const offer = await provider.create(issuer, configurations, {
      usePreAuth: true,
      code: PreAuthorizedCode('pre-auth-code-456'),
      txCode: txCodeInput,
    })

    assert.ok(offer.grants, 'grants should be defined')

    const preAuthGrant = offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']
    assert.ok(preAuthGrant, 'pre-authorized_code grant should be defined')

    assert.deepEqual(preAuthGrant.tx_code, expectedTxCode)
  })

  it('should create a credential offer using authorization code flow', async () => {
    const offer = await provider.create(issuer, configurations, {
      usePreAuth: false,
      state: 'xyz-state-789',
    })

    assert.deepEqual(offer.grants, {
      authorization_code: {
        issuer_state: 'xyz-state-789',
      },
    })
  })
})
