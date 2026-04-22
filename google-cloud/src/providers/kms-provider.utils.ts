import { constants, createPrivateKey, publicEncrypt } from 'node:crypto'

export const KMS_NOT_FOUND = 5
export const KMS_ALREADY_EXISTS = 6

export const kmsAlgorithmToJoseAlgorithm = (kmsAlgorithm?: unknown): string | null => {
  const algorithm = typeof kmsAlgorithm === 'string' ? kmsAlgorithm : ''
  switch (algorithm) {
    case 'EC_SIGN_P256_SHA256':
      return 'ES256'
    case 'EC_SIGN_P384_SHA384':
      return 'ES384'
    case 'RSA_SIGN_PKCS1_2048_SHA256':
    case 'RSA_SIGN_PKCS1_3072_SHA256':
    case 'RSA_SIGN_PKCS1_4096_SHA256':
      return 'RS256'
    case 'RSA_SIGN_PKCS1_4096_SHA512':
      return 'RS512'
    case 'RSA_SIGN_PSS_2048_SHA256':
    case 'RSA_SIGN_PSS_3072_SHA256':
    case 'RSA_SIGN_PSS_4096_SHA256':
      return 'PS256'
    case 'RSA_SIGN_PSS_4096_SHA512':
      return 'PS512'
    default:
      return null
  }
}

export const joseAlgorithmToKmsAlgorithm = (alg?: string): string | null => {
  switch (alg) {
    case 'ES256':
      return 'EC_SIGN_P256_SHA256'
    case 'ES384':
      return 'EC_SIGN_P384_SHA384'
    case 'RS256':
      return 'RSA_SIGN_PKCS1_2048_SHA256'
    case 'RS512':
      return 'RSA_SIGN_PKCS1_4096_SHA512'
    case 'PS256':
      return 'RSA_SIGN_PSS_2048_SHA256'
    case 'PS512':
      return 'RSA_SIGN_PSS_4096_SHA512'
    default:
      return null
  }
}

export const grpcCode = (error: unknown): number | undefined => {
  return typeof error === 'object' && error !== null && 'code' in error
    ? (error as { code?: number }).code
    : undefined
}

export const digestFieldName = (alg: string): 'sha256' | 'sha384' | 'sha512' | null => {
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

export const latestEnabledVersion = (versions: { name?: string | null }[]) => {
  return versions.reduce<{ name?: string | null } | null>((latest, current) => {
    if (!current.name) {
      return latest
    }
    if (!latest?.name) {
      return current
    }

    const currentVersion = Number(current.name.split('/').pop())
    const latestVersion = Number(latest.name.split('/').pop())
    if (Number.isNaN(currentVersion) || Number.isNaN(latestVersion)) {
      return current.name.localeCompare(latest.name) > 0 ? current : latest
    }
    return currentVersion > latestVersion ? current : latest
  }, null)
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

export const wrapPrivateKeyForImport = (privateKeyDer: Buffer, wrappingPem: string): Buffer => {
  return publicEncrypt(
    {
      key: wrappingPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    privateKeyDer
  )
}
