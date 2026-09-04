import { z } from 'zod'
import { jwkSchema } from './jwk.type'

export const encryptionPublicJwkSchema = jwkSchema.extend({
  alg: z.string(),
  kid: z.string(),
  use: z.literal('enc'),
})

export const encryptionKeyPairSchema = z.object({
  publicKey: encryptionPublicJwkSchema,
  privateKey: jwkSchema,
})

export const encryptionKeyEntrySchema = encryptionKeyPairSchema.extend({
  declaredAlg: z.string(),
})

export type EncryptionPublicJwk = z.infer<typeof encryptionPublicJwkSchema>
export type EncryptionKeyPair = z.infer<typeof encryptionKeyPairSchema>
export type EncryptionKeyEntry = z.infer<typeof encryptionKeyEntrySchema>
