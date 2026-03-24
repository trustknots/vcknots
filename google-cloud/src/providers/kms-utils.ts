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
