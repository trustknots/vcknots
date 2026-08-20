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
import { JwtPayload, ProofJwtHeader, SignatureKeyEntry } from '@trustknots/vcknots'
import { ErrorCodes, VcknotsError, raise } from '@trustknots/vcknots/errors'
import { KmsProviderOptions, resolveKmsClient } from './kms'
import {
  derSpkiToPem,
  digestAlgorithm,
  isKmsError,
  joseAlgorithmToKeySpec,
  joseAlgorithmToSigningAlgorithm,
  keySpecMatchesAlgorithm,
  kmsKeyAlias,
  toPkcs8Der,
  wrapPrivateKeyForImport,
} from './kms-provider.utils'

export type KmsSignatureKeyStoreConfig = {
  /** Lowercase noun used in log and error messages, e.g. 'issuer'. */
  subject: string
  /** KMS alias namespace the store owns, e.g. 'alias/vcknots/issuers/'. */
  aliasPrefix: string
  /** Tag applied to every key the store creates, so IAM can match on aws:ResourceTag. */
  tagKey: string
  /** Error code raised when signing is attempted without a key. */
  keyNotFoundError: ErrorCodes
}

/**
 * Extra surface the AWS KMS stores expose on top of the core provider interfaces, kept out of
 * those interfaces so the flow layer never sees it.
 *
 * IMPORTANT: the flow layer decides the algorithm — every call arrives here with `keyAlg`
 * already resolved (`options?.alg ?? 'ES256'`). `defaultAlg` therefore does NOT drive what gets
 * created; it only mirrors the flow's fallback so AWS-side callers stop repeating the literal.
 * Changing it will not change which algorithm the flow uses, so keep it in sync with the flow.
 */
export type KmsSignatureKeyStoreDefaults = {
  /** Mirror of the flow layer's fallback algorithm, for AWS-side callers only. */
  defaultAlg: string
}

/**
 * The issuer and verifier signature key stores differ only in their alias namespace, key tag
 * and key-not-found error code — the KMS interaction (generate, import, describe, sign) is
 * identical — so both are built from this factory.
 *
 * Subjects are typed as plain strings here; the branded `CredentialIssuer` / `ClientId` types
 * are reapplied by the provider that wraps this core.
 */
export const createKmsSignatureKeyStore = (
  config: KmsSignatureKeyStoreConfig,
  options?: KmsProviderOptions
) => {
  const kms = resolveKmsClient(options)
  const { subject, aliasPrefix, tagKey, keyNotFoundError } = config
  const Subject = `${subject.charAt(0).toUpperCase()}${subject.slice(1)}`
  const keyAlias = (id: string, alg: string) => {
    if (typeof alg !== 'string' || alg.trim().length === 0) {
      raise('internal_server_error', {
        message: `${Subject} key algorithm is required to build a KMS key alias`,
      })
    }
    return kmsKeyAlias(aliasPrefix, id, alg)
  }

  // A key that never got its alias is unusable and invisible to every later call, so it has to
  // be discarded or it just accumulates against the KMS key quota and the bill. Cleanup failures
  // are logged rather than thrown: they must not mask the error that triggered the cleanup.
  const discardOrphanKey = async (keyId: string) => {
    try {
      await kms.send(new ScheduleKeyDeletionCommand({ KeyId: keyId, PendingWindowInDays: 7 }))
    } catch (cleanupError) {
      if (isKmsError(cleanupError, 'NotFoundException')) {
        return
      }
      console.error(`Failed to discard the orphan KMS key ${keyId}: ${cleanupError}`)
    }
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
    // Mirrors the flow layer's fallback so the AWS app factories don't each repeat it. See
    // KmsSignatureKeyStoreDefaults: this does not decide the algorithm, the flow does.
    defaultAlg: 'ES256',

    async save(id: string, keyAlg: string, pair?: SignatureKeyEntry): Promise<void> {
      const declaredAlg = pair?.declaredAlg ?? keyAlg
      if (pair && pair.declaredAlg !== keyAlg) {
        raise('illegal_argument', {
          message: `The provided key pair algorithm ${pair.declaredAlg} does not match the requested key algorithm ${keyAlg}.`,
        })
      }

      const keySpec = joseAlgorithmToKeySpec(declaredAlg)
      if (!keySpec) {
        raise('internal_server_error', {
          message: `Unsupported ${subject} key algorithm: ${declaredAlg}`,
        })
      }

      if (pair && (declaredAlg.startsWith('RS') || declaredAlg.startsWith('PS'))) {
        raise('internal_server_error', {
          message: `Import for ${declaredAlg} requires RSA_AES wrapping (AES-KWP), which is not implemented`,
        })
      }

      const alias = keyAlias(id, declaredAlg)

      if (!pair) {
        const existing = await describeKey(alias)
        if (existing) {
          if (existing.KeyState !== KeyState.Enabled) {
            raise('internal_server_error', {
              message: `KMS key for the alias ${alias} is not usable: ${existing.KeyState}`,
            })
          }
          return
        }
        const created = await kms.send(
          new CreateKeyCommand({
            KeyUsage: KeyUsageType.SIGN_VERIFY,
            KeySpec: keySpec,
            Tags: [{ TagKey: tagKey, TagValue: 'true' }],
          })
        )
        const keyId = created.KeyMetadata?.KeyId
        if (!keyId) {
          raise('internal_server_error', { message: 'KMS CreateKey response is missing KeyId' })
        }
        try {
          await kms.send(new CreateAliasCommand({ AliasName: alias, TargetKeyId: keyId }))
        } catch (error) {
          // Either we lost the alias race (another writer created the key first) or the alias
          // call failed outright. Either way the key we just created never got its alias.
          await discardOrphanKey(keyId)
          if (isKmsError(error, 'AlreadyExistsException')) {
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
          Tags: [{ TagKey: tagKey, TagValue: 'true' }],
        })
      )
      const keyId = created.KeyMetadata?.KeyId
      if (!keyId) {
        raise('internal_server_error', { message: 'KMS CreateKey response is missing KeyId' })
      }

      try {
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
      } catch (error) {
        await discardOrphanKey(keyId)
        throw error
      }

      // The key material is in place but the key is still unaliased, so every failure below
      // leaves it as unreachable as a failed import would.
      try {
        await kms.send(new CreateAliasCommand({ AliasName: alias, TargetKeyId: keyId }))
      } catch (error) {
        if (isKmsError(error, 'AlreadyExistsException')) {
          try {
            await kms.send(new UpdateAliasCommand({ AliasName: alias, TargetKeyId: keyId }))
            return
          } catch (updateError) {
            await discardOrphanKey(keyId)
            throw updateError
          }
        }
        await discardOrphanKey(keyId)
        throw error
      }
    },

    async fetch(id: string, keyAlg: string): Promise<CryptoKey | null> {
      const alias = keyAlias(id, keyAlg)
      const metadata = await describeKey(alias)
      if (!metadata) {
        return null
      }
      if (metadata.KeyState !== KeyState.Enabled) {
        console.error(`KMS key is not enabled for ${subject} ${id}: ${metadata.KeyState}`)
        return null
      }
      if (!keySpecMatchesAlgorithm(metadata.KeySpec, keyAlg)) {
        console.error(`Unsupported KMS key spec for ${subject} ${id}: ${metadata.KeySpec}`)
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
        console.error(`Public key data is incomplete for ${subject} ${id}`)
        return null
      }

      return importSPKI(derSpkiToPem(publicKey.PublicKey), keyAlg)
    },

    async sign(
      id: string,
      keyAlg: string,
      jwtPayload: JwtPayload,
      jwtHeader: ProofJwtHeader
    ): Promise<string | null> {
      try {
        const alias = keyAlias(id, keyAlg)
        const metadata = await describeKey(alias)
        if (!metadata) {
          raise(keyNotFoundError, {
            message: `${Subject} private key not found.`,
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
            message: `Unsupported ${subject} key algorithm: ${keyAlg}`,
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
              raise(keyNotFoundError, {
                message: `${Subject} private key not found.`,
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
