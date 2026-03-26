import { z } from 'zod'
import { jwkSchema } from './jwk.type'

const PEM_LABELS =
  '(PUBLIC KEY|PRIVATE KEY|ENCRYPTED PRIVATE KEY|EC PRIVATE KEY|RSA PRIVATE KEY|CERTIFICATE|CERTIFICATE REQUEST|X509 CRL|PKCS7|PKCS8)'

const PEM_REGEX = new RegExp(
  `^\\s*-----BEGIN (${PEM_LABELS})-----[\\r\\n]+([A-Za-z0-9+/=\\r\\n]+)[\\r\\n]+-----END \\1-----\\s*$`
)

const PemStringSchema = z.string().refine(
  (val) => {
    const s = val.replace(/\r\n/g, '\n').trim()
    return PEM_REGEX.test(s)
  },
  { message: 'Invalid PEM format.' }
)

export const certificateSchema = z.array(PemStringSchema)

export const signatureKeyPairSchema = z.object({
  publicKey: jwkSchema,
  privateKey: jwkSchema,
})

export const tmpKeyMeta = z.object({
  format: z.enum(['pem', 'jwk']),
  declaredAlg: z.string(),
  kid: z.string().optional(),
})

export const signatureKeyEntrySchema = z.object({
  ...tmpKeyMeta.shape,
  publicKey: z.union([PemStringSchema, jwkSchema]).optional(),
  privateKey: z.union([PemStringSchema, jwkSchema]),
})

export type Certificate = z.infer<typeof certificateSchema>
export type SignatureKeyPair = z.infer<typeof signatureKeyPairSchema>
export type SignatureKeyEntry = z.infer<typeof signatureKeyEntrySchema>

export const Certificate = (value?: string | string[]) => certificateSchema.parse(value)
Certificate.schema = certificateSchema
