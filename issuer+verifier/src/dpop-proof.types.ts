export type ParsedDpopHeader =
  | { ok: true; proofJwt: string }
  | { ok: false; reason: 'missing' | 'duplicate' | 'malformed' }

export type DPoPProofVerifyContext = {
  htm: string
  htu: string
  nonce?: string
}

export type VerifiedDpopProof = {
  jwkThumbprint: string
  jti: string
  iat: number
  nonce?: string
}
