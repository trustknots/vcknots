import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { issueCredentialJwt } from '../../src/providers/issue-credential-jwt-vc-json.provider'
import { IssueCredentialProvider } from '../../src/providers/provider.types'
import { CredentialConfiguration, CredentialIssuer } from '../../src/credential-issuer.types'
import { ProofJwt } from '../../src/credential.types'
import { VcknotsError } from '../../src/errors/vcknots.error'
import { CredentialFormats } from '../../src/credential-request.types'

describe('issueCredential', () => {
  const provider: IssueCredentialProvider = issueCredentialJwt()

  const credentialIssuer = CredentialIssuer('https://issuer.example.com')
  const configuration: CredentialConfiguration = {
    format: 'jwt_vc_json',
    credential_definition: {
      type: ['VerifiableCredential', 'UniversityDegreeCredential'],
      credentialSubject: {
        given_name: {
          display: [
            {
              name: 'Given Name',
              locale: 'en-US',
            },
          ],
        },
        family_name: {
          display: [
            {
              name: 'Surname',
              locale: 'en-US',
            },
          ],
        },
        degree: {},
        gpa: {
          display: [
            {
              name: 'GPA',
            },
          ],
        },
      },
    },
    display: [
      {
        name: 'University Degree',
        locale: 'en-US',
        logo: {
          uri: 'https://example.com/logo.png',
          alt_text: 'University Logo',
        },
        background_color: '#12107c',
        text_color: '#FFFFFF',
      },
    ],
  }
  const proof: ProofJwt = {
    header: {
      typ: 'openid4vci-proof+jwt',
      alg: 'ES256',
      kid: 'did:example:123#key-1',
    },
    payload: {
      iss: 'did:example:123',
      aud: 'https://issuer.example.com',
      iat: 1671306000,
      nonce: 'tZl4S36D3a6B2d5C',
    },
  }

  it('should have correct kind, name, and single properties', () => {
    assert.equal(provider.kind, 'issue-credential-provider')
    assert.equal(provider.name, 'default-issue-credential-w3c-jwt-vc-json-provider')
    assert.strictEqual(provider.single, false)
  })

  it('should handle jwt_vc_json format', () => {
    assert.ok(provider.canHandle(CredentialFormats.JWT_VC_JSON))
  })

  it('should not handle other formats', () => {
    assert.ok(!provider.canHandle(CredentialFormats.LDP_VC))
  })

  it('should create a verifiable credential', () => {
    const vc = provider.createCredential(credentialIssuer, configuration, proof)

    assert.ok(vc)
    assert.ok(vc.id)
    assert.equal(typeof vc.id, 'string')
    assert.deepEqual(vc.type, ['VerifiableCredential', 'UniversityDegreeCredential'])
    assert.equal(vc.issuer, credentialIssuer)
    assert.ok(vc.issuanceDate)
    assert.ok(vc.credentialSubject)
    assert.equal(vc.credentialSubject.id, proof.header.kid)
  })

  it('should create a verifiable credential with claims', () => {
    const claims = {
      given_name: 'John',
      family_name: 'Doe',
      degree: 'Bachelor of Science',
      gpa: '4.0',
    }
    const vc = provider.createCredential(credentialIssuer, configuration, proof, claims)

    assert.ok(vc)
    assert.ok(vc.credentialSubject)
    assert.equal(vc.credentialSubject.given_name, 'John')
    assert.equal(vc.credentialSubject.family_name, 'Doe')
    assert.equal(vc.credentialSubject.degree, 'Bachelor of Science')
    assert.equal(vc.credentialSubject.gpa, '4.0')
  })

  it('should throw error if mandatory claim is missing', () => {
    const configurationWithMandatory: CredentialConfiguration = {
      ...configuration,
      credential_definition: {
        ...configuration.credential_definition,
        credentialSubject: {
          ...configuration.credential_definition.credentialSubject,
          given_name: {
            ...configuration.credential_definition.credentialSubject?.given_name,
            mandatory: true,
          },
        },
      },
    }
    const claims = {
      family_name: 'Doe',
    }
    assert.throws(
      () => provider.createCredential(credentialIssuer, configurationWithMandatory, proof, claims),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_CLAIMS')
        return true
      }
    )
  })

  it('should throw error if a mandatory claim is missing when multiple mandatory claims exist', () => {
    const configurationWithMandatory: CredentialConfiguration = {
      ...configuration,
      credential_definition: {
        ...configuration.credential_definition,
        credentialSubject: {
          ...configuration.credential_definition.credentialSubject,
          given_name: {
            ...configuration.credential_definition.credentialSubject?.given_name,
            mandatory: true,
          },
          family_name: {
            ...configuration.credential_definition.credentialSubject?.family_name,
            mandatory: true,
          },
        },
      },
    }
    const claims = {
      given_name: 'John',
    }
    assert.throws(
      () => provider.createCredential(credentialIssuer, configurationWithMandatory, proof, claims),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_CLAIMS')
        return true
      }
    )
  })

  it('should cast claims to correct type', () => {
    const configurationWithTypes: CredentialConfiguration = {
      ...configuration,
      credential_definition: {
        ...configuration.credential_definition,
        credentialSubject: {
          ...configuration.credential_definition.credentialSubject,
          given_name: {
            value_type: 'string',
          },
          age: {
            value_type: 'number',
          },
        },
      },
    }
    const claims = {
      given_name: 123,
      age: '25',
    }
    const vc = provider.createCredential(credentialIssuer, configurationWithTypes, proof, claims)

    assert.ok(vc)
    assert.ok(vc.credentialSubject)
    assert.equal(typeof vc.credentialSubject.given_name, 'string')
    assert.equal(vc.credentialSubject.given_name, '123')
    assert.equal(typeof vc.credentialSubject.age, 'number')
    assert.equal(vc.credentialSubject.age, 25)
  })

  it('should throw error if kid is missing in proof', () => {
    const proofWithoutKid: ProofJwt = { ...proof, header: { ...proof.header, kid: undefined } }
    assert.throws(
      () => provider.createCredential(credentialIssuer, configuration, proofWithoutKid),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_PROOF')
        return true
      }
    )
  })
})
