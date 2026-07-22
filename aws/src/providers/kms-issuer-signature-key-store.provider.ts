import { createHash } from 'node:crypto'
import {
  AlgorithmSpec,
  CreateAliasCommand,
  CreateKeyCommand,
  DescribeKeyCommand,
  ExpirationModelType,
  GetParametersForImportCommand,
  GetPublicKeyCommand,
  ImportKeyMaterialCommand,
  KeyMetadata,
  KeyState,
  KeyUsageType,
  MessageType,
  OriginType,
  ScheduleKeyDeletionCommand,
  SignCommand,
  UpdateAliasCommand,
  WrappingKeySpec,
} from '@aws-sdk/client-kms'
import { derToJose } from 'ecdsa-sig-formatter'
import { importSPKI } from 'jose'
import { IssuerSignatureKeyStoreProvider } from '@trustknots/vcknots/providers'
import { VcknotsError, raise } from '@trustknots/vcknots/errors'
import { CredentialIssuer } from '@trustknots/vcknots/issuer'
import { KmsProviderOptions, resolveKmsClient } from './kms'
import {
  derSpkiToPem,
  digestAlgorithm,
  isKmsError,
  joseAlgorithmToKeySpec,
  joseAlgorithmToSigningAlgorithm,
  keySpecMatchesAlgorithm,
  toPkcs8Der,
  wrapPrivateKeyForImport,
} from './kms-provider.utils'

export const kmsIssuerSignatureKeyStore = (
  options?: KmsProviderOptions
): IssuerSignatureKeyStoreProvider => {
  const kms = resolveKmsClient(options)
  const md5 = (issuer: CredentialIssuer) => createHash('md5').update(issuer).digest('base64url')
  const issuerKeyAlias = (issuer: CredentialIssuer, alg: string) => {
    if (typeof alg !== 'string' || alg.trim().length === 0) {
      raise('internal_server_error', {
        message: 'Issuer key algorithm is required to build a KMS key alias',
      })
    }
    return `alias/vcknots/issuers/${md5(issuer)}-${alg}`
  }

  const describeKey = async (alias: string): Promise<KeyMetadata | null> => {
    try {
      const { KeyMetadata: metadata } = await kms.send(new DescribeKeyCommand({ KeyId: alias }))
      return metadata ?? null
    } catch (error) {
      if (isKmsError(error, 'NotFoundException')) {
        return null
      }
      throw error
    }
  }

  return {
    kind: 'issuer-signature-key-store-provider',
    name: 'kms-issuer-signature-key-store-provider',
    single: true,

    async save(issuer, keyAlg, pair) {
      const declaredAlg = pair?.declaredAlg ?? keyAlg
      if (pair && pair.declaredAlg !== keyAlg) {
        raise('illegal_argument', {
          message: `The provided key pair algorithm ${pair.declaredAlg} does not match the requested key algorithm ${keyAlg}.`,
        })
      }

      const keySpec = joseAlgorithmToKeySpec(declaredAlg)
      if (!keySpec) {
        raise('internal_server_error', {
          message: `Unsupported issuer key algorithm: ${declaredAlg}`,
        })
      }

      if (pair && (declaredAlg.startsWith('RS') || declaredAlg.startsWith('PS'))) {
        raise('internal_server_error', {
          message: `Import for ${declaredAlg} requires RSA_AES wrapping (AES-KWP), which is not implemented`,
        })
      }

      const alias = issuerKeyAlias(issuer, declaredAlg)

      if (!pair) {
        if (await describeKey(alias)) {
          return
        }
        const created = await kms.send(
          new CreateKeyCommand({ KeyUsage: KeyUsageType.SIGN_VERIFY, KeySpec: keySpec })
        )
        const keyId = created.KeyMetadata?.KeyId
        if (!keyId) {
          raise('internal_server_error', { message: 'KMS CreateKey response is missing KeyId' })
        }
        try {
          await kms.send(new CreateAliasCommand({ AliasName: alias, TargetKeyId: keyId }))
        } catch (error) {
          if (isKmsError(error, 'AlreadyExistsException')) {
            // Lost the alias race: another writer created the key first. Discard our orphan key.
            await kms.send(
              new ScheduleKeyDeletionCommand({ KeyId: keyId, PendingWindowInDays: 7 })
            )
            return
          }
          throw error
        }
        return
      }

      // Import always creates a fresh key and repoints the alias, matching the GCP provider
      // which always imports a new crypto key version (the previous key is kept, not deleted).
      const created = await kms.send(
        new CreateKeyCommand({
          KeyUsage: KeyUsageType.SIGN_VERIFY,
          KeySpec: keySpec,
          Origin: OriginType.EXTERNAL,
        })
      )
      const keyId = created.KeyMetadata?.KeyId
      if (!keyId) {
        raise('internal_server_error', { message: 'KMS CreateKey response is missing KeyId' })
      }

      const importParams = await kms.send(
        new GetParametersForImportCommand({
          KeyId: keyId,
          WrappingAlgorithm: AlgorithmSpec.RSAES_OAEP_SHA_256,
          WrappingKeySpec: WrappingKeySpec.RSA_4096,
        })
      )
      if (!importParams.PublicKey || !importParams.ImportToken) {
        raise('internal_server_error', {
          message: 'KMS GetParametersForImport response is missing wrapping key or import token',
        })
      }

      const privateKeyDer = toPkcs8Der(pair.privateKey)
      const wrappedKey = wrapPrivateKeyForImport(privateKeyDer, importParams.PublicKey)
      await kms.send(
        new ImportKeyMaterialCommand({
          KeyId: keyId,
          ImportToken: importParams.ImportToken,
          EncryptedKeyMaterial: wrappedKey,
          ExpirationModel: ExpirationModelType.KEY_MATERIAL_DOES_NOT_EXPIRE,
        })
      )

      try {
        await kms.send(new CreateAliasCommand({ AliasName: alias, TargetKeyId: keyId }))
      } catch (error) {
        if (isKmsError(error, 'AlreadyExistsException')) {
          await kms.send(new UpdateAliasCommand({ AliasName: alias, TargetKeyId: keyId }))
          return
        }
        throw error
      }
    },

    async fetch(issuer, keyAlg) {
      const alias = issuerKeyAlias(issuer, keyAlg)
      const metadata = await describeKey(alias)
      if (!metadata) {
        return null
      }
      if (metadata.KeyState !== KeyState.Enabled) {
        console.error(`KMS key is not enabled for issuer ${issuer}: ${metadata.KeyState}`)
        return null
      }
      if (!keySpecMatchesAlgorithm(metadata.KeySpec, keyAlg)) {
        console.error(`Unsupported KMS key spec for issuer ${issuer}: ${metadata.KeySpec}`)
        return null
      }

      const publicKey = await (async () => {
        try {
          return await kms.send(new GetPublicKeyCommand({ KeyId: alias }))
        } catch (error) {
          if (isKmsError(error, 'NotFoundException')) {
            return null
          }
          throw error
        }
      })()
      if (!publicKey?.PublicKey) {
        console.error(`Public key data is incomplete for issuer ${issuer}`)
        return null
      }

      return importSPKI(derSpkiToPem(publicKey.PublicKey), keyAlg)
    },

    async sign(issuer, keyAlg, jwtPayload, jwtHeader) {
      try {
        const alias = issuerKeyAlias(issuer, keyAlg)
        const metadata = await describeKey(alias)
        if (!metadata) {
          raise('authz_issuer_key_not_found', {
            message: 'Issuer private key not found.',
          })
        }

        if (jwtHeader.alg !== keyAlg) {
          raise('illegal_argument', {
            message: `JWT header algorithm mismatch: header.alg=${jwtHeader.alg}, expected=${keyAlg}.`,
          })
        }

        const signingAlgorithm = joseAlgorithmToSigningAlgorithm(keyAlg)
        const digestAlg = digestAlgorithm(keyAlg)
        if (!signingAlgorithm || !digestAlg) {
          raise('internal_server_error', {
            message: `Unsupported issuer key algorithm: ${keyAlg}`,
          })
        }

        const encodedHeader = Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')
        const encodedPayload = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url')
        const signingInput = `${encodedHeader}.${encodedPayload}`
        const digest = createHash(digestAlg).update(Buffer.from(signingInput)).digest()

        const signed = await (async () => {
          try {
            return await kms.send(
              new SignCommand({
                KeyId: alias,
                Message: digest,
                MessageType: MessageType.DIGEST,
                SigningAlgorithm: signingAlgorithm,
              })
            )
          } catch (error) {
            if (isKmsError(error, 'NotFoundException')) {
              raise('authz_issuer_key_not_found', {
                message: 'Issuer private key not found.',
              })
            }
            throw error
          }
        })()

        if (!signed.Signature) {
          raise('internal_server_error', { message: 'KMS signature is missing' })
        }

        const signature = Buffer.from(signed.Signature)
        return keyAlg.startsWith('ES')
          ? derToJose(signature.toString('base64'), keyAlg)
          : signature.toString('base64url')
      } catch (error) {
        if (error instanceof VcknotsError) {
          throw error
        }
        raise('internal_server_error', { message: `sign error: ${error}` })
      }
    },
  }
}
