import assert from 'node:assert/strict'
import {
  constants,
  createHash,
  sign as cryptoSign,
  generateKeyPairSync,
  privateDecrypt,
} from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import {
  AlreadyExistsException,
  CreateAliasCommand,
  CreateKeyCommand,
  DescribeKeyCommand,
  GetParametersForImportCommand,
  GetPublicKeyCommand,
  ImportKeyMaterialCommand,
  KMSClient,
  NotFoundException,
  ScheduleKeyDeletionCommand,
  SignCommand,
  UpdateAliasCommand,
} from '@aws-sdk/client-kms'
import { mockClient } from 'aws-sdk-client-mock'
import { derToJose } from 'ecdsa-sig-formatter'
import { exportJWK } from 'jose'
import { VerifierClientId } from '@trustknots/vcknots/verifier'
import {
  VERIFIER_KEY_TAG_KEY,
  kmsVerifierSignatureKeyStore,
} from '../src/providers/kms-verifier-signature-key-store.provider'

const verifier = VerifierClientId('https://example.com/verifier')
const md5 = (value: string) => createHash('md5').update(value).digest('base64url')
const verifierKeyAlias = (alg: string) => `alias/vcknots/verifiers/${md5(verifier)}-${alg}`

const kmsMock = mockClient(KMSClient)

const notFound = () => new NotFoundException({ message: 'not found', $metadata: {} })
const alreadyExists = () => new AlreadyExistsException({ message: 'already exists', $metadata: {} })
const accessDenied = () => {
  const error = new Error('access denied')
  error.name = 'AccessDeniedException'
  return error
}

const generateEcPair = () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  return {
    privateKey,
    publicKey,
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    publicKeyDer: new Uint8Array(publicKey.export({ format: 'der', type: 'spki' })),
  }
}

// Stand-in for the KMS wrapping key pair returned by GetParametersForImport. The provider
// requests RSA_4096 but never inspects the key size, so a faster 2048-bit key is fine here.
const wrappingKeyPair = generateKeyPairSync('rsa', { modulusLength: 2048 })
const wrappingPublicKeyDer = new Uint8Array(
  wrappingKeyPair.publicKey.export({ format: 'der', type: 'spki' })
)
const importToken = new Uint8Array([1, 2, 3])

describe('kmsVerifierSignatureKeyStore', () => {
  const originalConsoleError = console.error

  afterEach(() => {
    kmsMock.reset()
    console.error = originalConsoleError
  })

  const createProvider = () =>
    kmsVerifierSignatureKeyStore({ client: kmsMock as unknown as KMSClient })

  it('should have correct provider metadata', () => {
    const provider = createProvider()
    assert.equal(provider.kind, 'verifier-signature-key-store-provider')
    assert.equal(provider.name, 'kms-verifier-signature-key-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save an ES256 verifier key by importing it into KMS', async () => {
    const { privateKey, privateKeyPem } = generateEcPair()
    kmsMock.on(CreateKeyCommand).resolves({ KeyMetadata: { KeyId: 'imported-key' } as never })
    kmsMock.on(GetParametersForImportCommand).resolves({
      PublicKey: wrappingPublicKeyDer,
      ImportToken: importToken,
    })
    kmsMock.on(ImportKeyMaterialCommand).resolves({})
    kmsMock.on(CreateAliasCommand).resolves({})

    const provider = createProvider()
    await provider.save(verifier, 'ES256', {
      format: 'pem',
      declaredAlg: 'ES256',
      privateKey: privateKeyPem,
    })

    assert.deepEqual(kmsMock.commandCalls(CreateKeyCommand)[0]?.args[0].input, {
      KeyUsage: 'SIGN_VERIFY',
      KeySpec: 'ECC_NIST_P256',
      Origin: 'EXTERNAL',
      Tags: [{ TagKey: VERIFIER_KEY_TAG_KEY, TagValue: 'true' }],
    })
    assert.deepEqual(kmsMock.commandCalls(GetParametersForImportCommand)[0]?.args[0].input, {
      KeyId: 'imported-key',
      WrappingAlgorithm: 'RSAES_OAEP_SHA_256',
      WrappingKeySpec: 'RSA_4096',
    })

    const importInput = kmsMock.commandCalls(ImportKeyMaterialCommand)[0]?.args[0].input
    assert.equal(importInput?.KeyId, 'imported-key')
    assert.equal(importInput?.ImportToken, importToken)
    assert.equal(importInput?.ExpirationModel, 'KEY_MATERIAL_DOES_NOT_EXPIRE')
    // The wrapped material must be the private key OAEP-SHA256-encrypted to the wrapping key.
    const unwrapped = privateDecrypt(
      {
        key: wrappingKeyPair.privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(importInput?.EncryptedKeyMaterial as Uint8Array)
    )
    assert.deepEqual(unwrapped, privateKey.export({ format: 'der', type: 'pkcs8' }))

    assert.deepEqual(kmsMock.commandCalls(CreateAliasCommand)[0]?.args[0].input, {
      AliasName: verifierKeyAlias('ES256'),
      TargetKeyId: 'imported-key',
    })
    assert.equal(kmsMock.commandCalls(UpdateAliasCommand).length, 0)
  })

  it('should repoint the alias via UpdateAlias when re-saving an imported pair', async () => {
    const { privateKeyPem } = generateEcPair()
    kmsMock.on(CreateKeyCommand).resolves({ KeyMetadata: { KeyId: 'new-key' } as never })
    kmsMock.on(GetParametersForImportCommand).resolves({
      PublicKey: wrappingPublicKeyDer,
      ImportToken: importToken,
    })
    kmsMock.on(ImportKeyMaterialCommand).resolves({})
    kmsMock.on(CreateAliasCommand).rejects(alreadyExists())
    kmsMock.on(UpdateAliasCommand).resolves({})

    const provider = createProvider()
    await provider.save(verifier, 'ES256', {
      format: 'pem',
      declaredAlg: 'ES256',
      privateKey: privateKeyPem,
    })

    assert.deepEqual(kmsMock.commandCalls(UpdateAliasCommand)[0]?.args[0].input, {
      AliasName: verifierKeyAlias('ES256'),
      TargetKeyId: 'new-key',
    })
    // The previously aliased key must be kept (parity with GCP retaining old versions).
    assert.equal(kmsMock.commandCalls(ScheduleKeyDeletionCommand).length, 0)
  })

  it('should reject save when pair algorithm does not match keyAlg', async () => {
    const { privateKeyPem } = generateEcPair()

    const provider = createProvider()
    await assert.rejects(
      provider.save(verifier, 'ES384', {
        format: 'pem',
        declaredAlg: 'ES256',
        privateKey: privateKeyPem,
      }),
      (error: Error) => {
        assert.equal(error.name, 'illegal_argument')
        assert.match(error.message, /does not match the requested key algorithm/)
        return true
      }
    )

    assert.equal(kmsMock.commandCalls(CreateKeyCommand).length, 0)
  })

  it('should fail save for unsupported algorithms', async () => {
    const provider = createProvider()
    await assert.rejects(
      provider.save(verifier, 'unsupported', {
        format: 'jwk',
        declaredAlg: 'unsupported',
        privateKey: { kty: 'EC' },
      }),
      (error: Error) => {
        assert.equal(error.name, 'internal_server_error')
        assert.match(error.message, /Unsupported verifier key algorithm/)
        return true
      }
    )

    assert.equal(kmsMock.commandCalls(CreateKeyCommand).length, 0)
  })

  it('should reject RS256 pair import as unimplemented RSA_AES wrapping', async () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()

    const provider = createProvider()
    await assert.rejects(
      provider.save(verifier, 'RS256', {
        format: 'pem',
        declaredAlg: 'RS256',
        privateKey: privateKeyPem,
      }),
      (error: Error) => {
        assert.equal(error.name, 'internal_server_error')
        assert.match(error.message, /RSA_AES wrapping/)
        return true
      }
    )

    assert.equal(kmsMock.commandCalls(CreateKeyCommand).length, 0)
  })

  it('should fail save when GetParametersForImport response is incomplete', async () => {
    const { privateKeyPem } = generateEcPair()
    kmsMock.on(CreateKeyCommand).resolves({ KeyMetadata: { KeyId: 'imported-key' } as never })
    kmsMock.on(GetParametersForImportCommand).resolves({ PublicKey: wrappingPublicKeyDer })
    kmsMock.on(ScheduleKeyDeletionCommand).resolves({})

    const provider = createProvider()
    await assert.rejects(
      provider.save(verifier, 'ES256', {
        format: 'pem',
        declaredAlg: 'ES256',
        privateKey: privateKeyPem,
      }),
      (error: Error) => {
        assert.equal(error.name, 'internal_server_error')
        assert.match(error.message, /missing wrapping key or import token/)
        return true
      }
    )

    assert.equal(kmsMock.commandCalls(ImportKeyMaterialCommand).length, 0)
    assert.deepEqual(kmsMock.commandCalls(ScheduleKeyDeletionCommand)[0]?.args[0].input, {
      KeyId: 'imported-key',
      PendingWindowInDays: 7,
    })
  })

  it('should discard the orphan EXTERNAL key when the import fails', async () => {
    const { privateKeyPem } = generateEcPair()
    kmsMock.on(CreateKeyCommand).resolves({ KeyMetadata: { KeyId: 'orphan-external-key' } as never })
    kmsMock.on(GetParametersForImportCommand).resolves({
      PublicKey: wrappingPublicKeyDer,
      ImportToken: importToken,
    })
    kmsMock.on(ImportKeyMaterialCommand).rejects(accessDenied())
    kmsMock.on(ScheduleKeyDeletionCommand).resolves({})

    const provider = createProvider()
    await assert.rejects(
      provider.save(verifier, 'ES256', {
        format: 'pem',
        declaredAlg: 'ES256',
        privateKey: privateKeyPem,
      }),
      /access denied/
    )

    assert.deepEqual(kmsMock.commandCalls(ScheduleKeyDeletionCommand)[0]?.args[0].input, {
      KeyId: 'orphan-external-key',
      PendingWindowInDays: 7,
    })
    assert.equal(kmsMock.commandCalls(CreateAliasCommand).length, 0)
  })

  it('should still surface the import failure when discarding the orphan key fails', async () => {
    const errors: unknown[][] = []
    console.error = (...args: unknown[]) => {
      errors.push(args)
    }
    const { privateKeyPem } = generateEcPair()
    kmsMock.on(CreateKeyCommand).resolves({ KeyMetadata: { KeyId: 'orphan-external-key' } as never })
    kmsMock.on(GetParametersForImportCommand).resolves({
      PublicKey: wrappingPublicKeyDer,
      ImportToken: importToken,
    })
    kmsMock.on(ImportKeyMaterialCommand).rejects(accessDenied())
    kmsMock.on(ScheduleKeyDeletionCommand).rejects(new Error('cleanup failed'))

    const provider = createProvider()
    await assert.rejects(
      provider.save(verifier, 'ES256', {
        format: 'pem',
        declaredAlg: 'ES256',
        privateKey: privateKeyPem,
      }),
      /access denied/
    )

    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /Failed to discard the orphan KMS key/)
  })

  it('should discard the imported key when CreateAlias fails outright', async () => {
    const { privateKeyPem } = generateEcPair()
    kmsMock.on(CreateKeyCommand).resolves({ KeyMetadata: { KeyId: 'imported-key' } as never })
    kmsMock.on(GetParametersForImportCommand).resolves({
      PublicKey: wrappingPublicKeyDer,
      ImportToken: importToken,
    })
    kmsMock.on(ImportKeyMaterialCommand).resolves({})
    kmsMock.on(CreateAliasCommand).rejects(accessDenied())
    kmsMock.on(ScheduleKeyDeletionCommand).resolves({})

    const provider = createProvider()
    await assert.rejects(
      provider.save(verifier, 'ES256', {
        format: 'pem',
        declaredAlg: 'ES256',
        privateKey: privateKeyPem,
      }),
      /access denied/
    )

    // The key material is in place but the key never got its alias, so it is unreachable.
    assert.deepEqual(kmsMock.commandCalls(ScheduleKeyDeletionCommand)[0]?.args[0].input, {
      KeyId: 'imported-key',
      PendingWindowInDays: 7,
    })
  })

  it('should discard the imported key when UpdateAlias fails', async () => {
    const { privateKeyPem } = generateEcPair()
    kmsMock.on(CreateKeyCommand).resolves({ KeyMetadata: { KeyId: 'imported-key' } as never })
    kmsMock.on(GetParametersForImportCommand).resolves({
      PublicKey: wrappingPublicKeyDer,
      ImportToken: importToken,
    })
    kmsMock.on(ImportKeyMaterialCommand).resolves({})
    kmsMock.on(CreateAliasCommand).rejects(alreadyExists())
    kmsMock.on(UpdateAliasCommand).rejects(accessDenied())
    kmsMock.on(ScheduleKeyDeletionCommand).resolves({})

    const provider = createProvider()
    await assert.rejects(
      provider.save(verifier, 'ES256', {
        format: 'pem',
        declaredAlg: 'ES256',
        privateKey: privateKeyPem,
      }),
      /access denied/
    )

    assert.deepEqual(kmsMock.commandCalls(ScheduleKeyDeletionCommand)[0]?.args[0].input, {
      KeyId: 'imported-key',
      PendingWindowInDays: 7,
    })
  })

  it('should create a KMS-managed key when pair is not provided', async () => {
    kmsMock.on(DescribeKeyCommand).rejects(notFound())
    kmsMock.on(CreateKeyCommand).resolves({ KeyMetadata: { KeyId: 'generated-key' } as never })
    kmsMock.on(CreateAliasCommand).resolves({})

    const provider = createProvider()
    await provider.save(verifier, 'ES256')

    assert.deepEqual(kmsMock.commandCalls(CreateKeyCommand)[0]?.args[0].input, {
      KeyUsage: 'SIGN_VERIFY',
      KeySpec: 'ECC_NIST_P256',
      Tags: [{ TagKey: VERIFIER_KEY_TAG_KEY, TagValue: 'true' }],
    })
    assert.deepEqual(kmsMock.commandCalls(CreateAliasCommand)[0]?.args[0].input, {
      AliasName: verifierKeyAlias('ES256'),
      TargetKeyId: 'generated-key',
    })
    assert.equal(kmsMock.commandCalls(GetParametersForImportCommand).length, 0)
    assert.equal(kmsMock.commandCalls(ImportKeyMaterialCommand).length, 0)
  })

  it('should be a no-op when the alias already exists and pair is not provided', async () => {
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'existing-key', KeyState: 'Enabled' } as never,
    })

    const provider = createProvider()
    await provider.save(verifier, 'ES256')

    assert.equal(kmsMock.commandCalls(CreateKeyCommand).length, 0)
    assert.equal(kmsMock.commandCalls(CreateAliasCommand).length, 0)
  })

  it('should fail save when the aliased key is not in a usable state', async () => {
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'existing-key', KeyState: 'PendingDeletion' } as never,
    })

    const provider = createProvider()
    await assert.rejects(provider.save(verifier, 'ES256'), (error: Error) => {
      assert.equal(error.name, 'internal_server_error')
      assert.match(error.message, /is not usable: PendingDeletion/)
      return true
    })

    assert.equal(kmsMock.commandCalls(CreateKeyCommand).length, 0)
  })

  it('should fail save when the CreateKey response has no KeyId', async () => {
    kmsMock.on(DescribeKeyCommand).rejects(notFound())
    kmsMock.on(CreateKeyCommand).resolves({})

    const provider = createProvider()
    await assert.rejects(provider.save(verifier, 'ES256'), (error: Error) => {
      assert.equal(error.name, 'internal_server_error')
      assert.match(error.message, /CreateKey response is missing KeyId/)
      return true
    })

    assert.equal(kmsMock.commandCalls(CreateAliasCommand).length, 0)
  })

  it('should schedule deletion of the orphan key when losing the alias race', async () => {
    kmsMock.on(DescribeKeyCommand).rejects(notFound())
    kmsMock.on(CreateKeyCommand).resolves({ KeyMetadata: { KeyId: 'orphan-key' } as never })
    kmsMock.on(CreateAliasCommand).rejects(alreadyExists())
    kmsMock.on(ScheduleKeyDeletionCommand).resolves({})

    const provider = createProvider()
    await provider.save(verifier, 'ES256')

    assert.deepEqual(kmsMock.commandCalls(ScheduleKeyDeletionCommand)[0]?.args[0].input, {
      KeyId: 'orphan-key',
      PendingWindowInDays: 7,
    })
  })

  it('should discard the generated key when CreateAlias fails outright', async () => {
    kmsMock.on(DescribeKeyCommand).rejects(notFound())
    kmsMock.on(CreateKeyCommand).resolves({ KeyMetadata: { KeyId: 'orphan-key' } as never })
    kmsMock.on(CreateAliasCommand).rejects(accessDenied())
    kmsMock.on(ScheduleKeyDeletionCommand).resolves({})

    const provider = createProvider()
    await assert.rejects(provider.save(verifier, 'ES256'), /access denied/)

    assert.deepEqual(kmsMock.commandCalls(ScheduleKeyDeletionCommand)[0]?.args[0].input, {
      KeyId: 'orphan-key',
      PendingWindowInDays: 7,
    })
  })

  it('should rethrow non-NotFound errors from DescribeKey on save', async () => {
    kmsMock.on(DescribeKeyCommand).rejects(accessDenied())

    const provider = createProvider()
    await assert.rejects(provider.save(verifier, 'ES256'), /access denied/)

    assert.equal(kmsMock.commandCalls(CreateKeyCommand).length, 0)
  })

  it('should fetch the public key when KMS data is valid', async () => {
    const { publicKey, publicKeyDer } = generateEcPair()
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'key-1', KeyState: 'Enabled', KeySpec: 'ECC_NIST_P256' } as never,
    })
    kmsMock.on(GetPublicKeyCommand).resolves({ PublicKey: publicKeyDer })

    const provider = createProvider()
    const key = await provider.fetch(verifier, 'ES256')

    assert.ok(key)
    assert.deepEqual(await exportJWK(key), await exportJWK(publicKey))
    assert.equal(
      kmsMock.commandCalls(GetPublicKeyCommand)[0]?.args[0].input.KeyId,
      verifierKeyAlias('ES256')
    )
  })

  it('should reject an empty key algorithm before calling KMS', async () => {
    const provider = createProvider()
    await assert.rejects(provider.fetch(verifier, '  '), (error: Error) => {
      assert.equal(error.name, 'internal_server_error')
      assert.match(error.message, /Verifier key algorithm is required/)
      return true
    })

    assert.equal(kmsMock.commandCalls(DescribeKeyCommand).length, 0)
  })

  it('should return null from fetch when the key does not exist', async () => {
    kmsMock.on(DescribeKeyCommand).rejects(notFound())

    const provider = createProvider()
    assert.equal(await provider.fetch(verifier, 'ES256'), null)
  })

  it('should return null from fetch when the key is not enabled', async () => {
    const errors: unknown[][] = []
    console.error = (...args: unknown[]) => {
      errors.push(args)
    }
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'key-1', KeyState: 'Disabled', KeySpec: 'ECC_NIST_P256' } as never,
    })

    const provider = createProvider()
    assert.equal(await provider.fetch(verifier, 'ES256'), null)
    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /not enabled/)
  })

  it('should return null from fetch when the key spec does not match the algorithm', async () => {
    const errors: unknown[][] = []
    console.error = (...args: unknown[]) => {
      errors.push(args)
    }
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'key-1', KeyState: 'Enabled', KeySpec: 'RSA_2048' } as never,
    })

    const provider = createProvider()
    assert.equal(await provider.fetch(verifier, 'ES256'), null)
    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /Unsupported KMS key spec/)
  })

  it('should return null from fetch when GetPublicKey reports the key gone', async () => {
    const errors: unknown[][] = []
    console.error = (...args: unknown[]) => {
      errors.push(args)
    }
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'key-1', KeyState: 'Enabled', KeySpec: 'ECC_NIST_P256' } as never,
    })
    kmsMock.on(GetPublicKeyCommand).rejects(notFound())

    const provider = createProvider()
    assert.equal(await provider.fetch(verifier, 'ES256'), null)
    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /Public key data is incomplete/)
  })

  it('should return null from fetch when the public key data is incomplete', async () => {
    const errors: unknown[][] = []
    console.error = (...args: unknown[]) => {
      errors.push(args)
    }
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'key-1', KeyState: 'Enabled', KeySpec: 'ECC_NIST_P256' } as never,
    })
    kmsMock.on(GetPublicKeyCommand).resolves({})

    const provider = createProvider()
    assert.equal(await provider.fetch(verifier, 'ES256'), null)
    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /Public key data is incomplete/)
  })

  it('should rethrow non-NotFound errors from DescribeKey on fetch', async () => {
    kmsMock.on(DescribeKeyCommand).rejects(accessDenied())

    const provider = createProvider()
    await assert.rejects(provider.fetch(verifier, 'ES256'), /access denied/)
  })

  it('should sign an ES256 JAR and convert the DER signature to JOSE format', async () => {
    const { privateKey } = generateEcPair()
    const derSignature = cryptoSign('sha256', createHash('sha256').update('fixture').digest(), {
      key: privateKey,
      dsaEncoding: 'der',
    })
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'key-1', KeyState: 'Enabled', KeySpec: 'ECC_NIST_P256' } as never,
    })
    kmsMock.on(SignCommand).resolves({ Signature: new Uint8Array(derSignature) })
    const jwtHeader = { alg: 'ES256', typ: 'oauth-authz-req+jwt', kid: 'thumbprint' }
    const jwtPayload = { client_id: verifier, nonce: 'nonce-123' }

    const provider = createProvider()
    const result = await provider.sign(verifier, 'ES256', jwtPayload, jwtHeader)

    assert.equal(result, derToJose(derSignature.toString('base64'), 'ES256'))
    const encodedHeader = Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')
    const encodedPayload = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url')
    const expectedDigest = createHash('sha256')
      .update(Buffer.from(`${encodedHeader}.${encodedPayload}`))
      .digest()
    const signInput = kmsMock.commandCalls(SignCommand)[0]?.args[0].input
    assert.equal(signInput?.KeyId, verifierKeyAlias('ES256'))
    assert.equal(signInput?.MessageType, 'DIGEST')
    assert.equal(signInput?.SigningAlgorithm, 'ECDSA_SHA_256')
    assert.deepEqual(Buffer.from(signInput?.Message as Uint8Array), expectedDigest)
  })

  it('should sign an RS256 JAR and return the raw signature as base64url', async () => {
    const signature = new Uint8Array(createHash('sha512').update('rsa-fixture').digest())
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'key-1', KeyState: 'Enabled', KeySpec: 'RSA_2048' } as never,
    })
    kmsMock.on(SignCommand).resolves({ Signature: signature })

    const provider = createProvider()
    const result = await provider.sign(verifier, 'RS256', { client_id: verifier }, {
      alg: 'RS256',
      typ: 'oauth-authz-req+jwt',
    })

    assert.equal(result, Buffer.from(signature).toString('base64url'))
    assert.equal(
      kmsMock.commandCalls(SignCommand)[0]?.args[0].input.SigningAlgorithm,
      'RSASSA_PKCS1_V1_5_SHA_256'
    )
  })

  it('should fail sign when jwtHeader.alg conflicts with keyAlg', async () => {
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'key-1', KeyState: 'Enabled', KeySpec: 'ECC_NIST_P256' } as never,
    })

    const provider = createProvider()
    await assert.rejects(
      provider.sign(verifier, 'ES256', { client_id: verifier }, { alg: 'RS256', typ: 'JWT' }),
      (error: Error) => {
        assert.equal(error.name, 'illegal_argument')
        assert.match(error.message, /algorithm mismatch/)
        return true
      }
    )
  })

  it('should fail sign when jwtHeader.alg is missing', async () => {
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'key-1', KeyState: 'Enabled', KeySpec: 'ECC_NIST_P256' } as never,
    })

    const provider = createProvider()
    await assert.rejects(
      provider.sign(verifier, 'ES256', { client_id: verifier }, { typ: 'JWT' } as never),
      (error: Error) => {
        assert.equal(error.name, 'illegal_argument')
        assert.match(error.message, /algorithm mismatch/)
        return true
      }
    )
  })

  it('should map a missing key to authz_verifier_key_not_found on sign', async () => {
    kmsMock.on(DescribeKeyCommand).rejects(notFound())

    const provider = createProvider()
    await assert.rejects(
      provider.sign(verifier, 'ES256', { client_id: verifier }, { alg: 'ES256', typ: 'JWT' }),
      (error: Error) => {
        assert.equal(error.name, 'authz_verifier_key_not_found')
        assert.match(error.message, /Verifier private key not found/)
        return true
      }
    )
  })

  it('should map NotFound from Sign to authz_verifier_key_not_found', async () => {
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'key-1', KeyState: 'Enabled', KeySpec: 'ECC_NIST_P256' } as never,
    })
    kmsMock.on(SignCommand).rejects(notFound())

    const provider = createProvider()
    await assert.rejects(
      provider.sign(verifier, 'ES256', { client_id: verifier }, { alg: 'ES256', typ: 'JWT' }),
      (error: Error) => {
        assert.equal(error.name, 'authz_verifier_key_not_found')
        assert.match(error.message, /Verifier private key not found/)
        return true
      }
    )
  })

  it('should wrap unexpected sign failures in an internal_server_error', async () => {
    kmsMock.on(DescribeKeyCommand).rejects(accessDenied())

    const provider = createProvider()
    await assert.rejects(
      provider.sign(verifier, 'ES256', { client_id: verifier }, { alg: 'ES256', typ: 'JWT' }),
      (error: Error) => {
        assert.equal(error.name, 'internal_server_error')
        assert.match(error.message, /access denied/)
        return true
      }
    )
  })

  it('should fail sign when the KMS response has no signature', async () => {
    kmsMock.on(DescribeKeyCommand).resolves({
      KeyMetadata: { KeyId: 'key-1', KeyState: 'Enabled', KeySpec: 'ECC_NIST_P256' } as never,
    })
    kmsMock.on(SignCommand).resolves({})

    const provider = createProvider()
    await assert.rejects(
      provider.sign(verifier, 'ES256', { client_id: verifier }, { alg: 'ES256', typ: 'JWT' }),
      (error: Error) => {
        assert.equal(error.name, 'internal_server_error')
        assert.match(error.message, /KMS signature is missing/)
        return true
      }
    )
  })
})
