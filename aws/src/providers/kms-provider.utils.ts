import { constants, createPrivateKey, createPublicKey, publicEncrypt } from 'node:crypto'
import { KeySpec, SigningAlgorithmSpec } from '@aws-sdk/client-kms'

export const joseAlgorithmToKeySpec = (alg?: string): KeySpec | null => {
  switch (alg) {
    case 'ES256':
      return KeySpec.ECC_NIST_P256
    case 'ES384':
      return KeySpec.ECC_NIST_P384
    case 'RS256':
      return KeySpec.RSA_2048
    case 'RS512':
      return KeySpec.RSA_4096
    case 'PS256':
      return KeySpec.RSA_2048
    case 'PS512':
      return KeySpec.RSA_4096
    default:
      return null
  }
}

export const joseAlgorithmToSigningAlgorithm = (alg?: string): SigningAlgorithmSpec | null => {
  switch (alg) {
    case 'ES256':
      return SigningAlgorithmSpec.ECDSA_SHA_256
    case 'ES384':
      return SigningAlgorithmSpec.ECDSA_SHA_384
    case 'RS256':
      return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256
    case 'RS512':
      return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512
    case 'PS256':
      return SigningAlgorithmSpec.RSASSA_PSS_SHA_256
    case 'PS512':
      return SigningAlgorithmSpec.RSASSA_PSS_SHA_512
    default:
      return null
  }
}

/**
 * Unlike Cloud KMS — where the padding scheme is baked into the key version's algorithm
 * (RSA_SIGN_PKCS1_2048_SHA256 vs RSA_SIGN_PSS_2048_SHA256) — AWS KMS picks the padding at
 * Sign time via SigningAlgorithm, so a single RSA_2048 key serves both RS256 and PS256
 * (likewise RSA_4096 for RS512/PS512). RS256 and PS256 are therefore indistinguishable
 * here, and there is nothing to distinguish: the key material is identical and both
 * signatures are available on it. The jose alg is carried in the key alias instead.
 *
 * This still catches the mismatches that do matter: an alias pointing at an ECC key when
 * an RSA alg was requested, ES256 vs ES384, or RS256 (RSA_2048) vs RS512 (RSA_4096).
 */
export const keySpecMatchesAlgorithm = (keySpec: unknown, alg: string): boolean => {
  return typeof keySpec === 'string' && keySpec === joseAlgorithmToKeySpec(alg)
}

export const digestAlgorithm = (alg: string): 'sha256' | 'sha384' | 'sha512' | null => {
  switch (alg) {
    case 'ES256':
    case 'RS256':
    case 'PS256':
      return 'sha256'
    case 'ES384':
      return 'sha384'
    case 'RS512':
    case 'PS512':
      return 'sha512'
    default:
      return null
  }
}

export const isKmsError = (error: unknown, name: string): boolean => {
  return error instanceof Error && error.name === name
}

export const toPkcs8Der = (privateKey: unknown): Buffer => {
  if (typeof privateKey === 'string') {
    const key = createPrivateKey(privateKey)
    return key.export({ format: 'der', type: 'pkcs8' }) as Buffer
  }
  const key = createPrivateKey({
    key: privateKey as unknown as import('node:crypto').JsonWebKey,
    format: 'jwk',
  })
  return key.export({ format: 'der', type: 'pkcs8' }) as Buffer
}

/**
 * Wraps a PKCS#8 DER private key with the KMS-provided wrapping public key (DER SPKI)
 * using RSAES_OAEP_SHA_256, for ImportKeyMaterial.
 */
export const wrapPrivateKeyForImport = (
  privateKeyDer: Buffer,
  wrappingPublicKeyDer: Uint8Array
): Buffer => {
  const wrappingKey = createPublicKey({
    key: Buffer.from(wrappingPublicKeyDer),
    format: 'der',
    type: 'spki',
  })
  return publicEncrypt(
    {
      key: wrappingKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    privateKeyDer
  )
}

export const derSpkiToPem = (publicKeyDer: Uint8Array): string => {
  const key = createPublicKey({
    key: Buffer.from(publicKeyDer),
    format: 'der',
    type: 'spki',
  })
  return key.export({ format: 'pem', type: 'spki' }) as string
}
