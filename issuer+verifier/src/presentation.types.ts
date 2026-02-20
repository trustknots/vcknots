import { verifiableCredentialSchema, jwtVcJsonSchema } from './credential.types'
import { z } from 'zod'

export enum ProofTypes {
  JWT = 'jwt',
}

export const jwtVpJsonHeaderSchema = z.object({
  alg: z.string(),
  typ: z.literal('JWT'),
  kid: z.string().optional(),
})

export const jwtVpJsonPayloadSchema = <T extends z.ZodType>(t: T) =>
  z.object({
    vp: verifiablePresentationSchema(t),
    iss: z.string().optional(), // issuer
    aud: z.string().optional(), // audience
    nbf: z.number().optional(), // issuanceDate
    exp: z.number().optional(), // expirationDate
    jti: z.string().optional(), // id of the verifiable credential
    nonce: z.string(), // TODO: we have to discuss whether this should be optional or not (not compliant with the spec)
  })

export const jwtVpJsonSchema = <T extends z.ZodType>(t: T) =>
  z.object({
    header: jwtVpJsonHeaderSchema,
    payload: jwtVpJsonPayloadSchema(t),
  })

export const verifiablePresentationSchema = <T extends z.ZodType>(t: T) =>
  z.object({
    '@context': z.array(z.string()).optional(),
    id: z.string().url().optional(),
    type: z.array(z.string()),
    verifiableCredential: z.array(z.string().or(verifiableCredentialSchema(jwtVcJsonSchema(t)))),
    holder: z.string().url().optional(),
    nonce: z.string().optional(),
  })

export type VerifiablePresentation<T extends Record<string, unknown> = Record<string, unknown>> =
  z.infer<ReturnType<typeof jwtVpJsonPayloadSchema<z.ZodType<T>>>>
export type JwtVpJson<T extends Record<string, unknown> = Record<string, unknown>> = z.infer<
  ReturnType<typeof jwtVpJsonSchema<z.ZodType<T>>>
>

// RFC 9901: Selective Disclosure for JSON Web Tokens (SD-JWT)
export const sdJwtArrayDisclosureDigestSchema = z.object({
  '...': z.string(),
})

export const sdJwtPayloadValueSchema: z.ZodType = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    sdJwtArrayDisclosureDigestSchema,
    z.array(sdJwtPayloadValueSchema),
    z.record(z.string(), sdJwtPayloadValueSchema),
  ])
)

export const sdJwtPayloadSchema = z.record(z.string(), sdJwtPayloadValueSchema).and(
  z.object({
    _sd: z.array(z.string()).optional(),
    // RFC 9901 4.1.1: hash algorithm used for disclosure digest creation
    _sd_alg: z.string().optional(),
    // RFC 9901 4.1.2: key binding confirmation claim (RFC 7800)
    cnf: z
      .object({
        jwk: z.record(z.string(), sdJwtPayloadValueSchema).optional(),
      })
      .catchall(sdJwtPayloadValueSchema)
      .optional(),
  })
)

export type SdJwtArrayDisclosureDigest = z.infer<typeof sdJwtArrayDisclosureDigestSchema>
export type SdJwtPayloadValue = z.infer<typeof sdJwtPayloadValueSchema>
export type SdJwtPayload = z.infer<typeof sdJwtPayloadSchema>

export const jwtVpOrSdJwtPayloadSchema = <T extends z.ZodType>(t: T) =>
  z.union([jwtVpJsonPayloadSchema(t), sdJwtPayloadValueSchema])

export type JwtVpOrSdJwtPayload<T extends Record<string, unknown> = Record<string, unknown>> =
  z.infer<ReturnType<typeof jwtVpOrSdJwtPayloadSchema<z.ZodType<T>>>>
