import { verifiableCredentialSchema, jwtVcJsonSchema } from './credential.types'
import { jwkSchema } from './jwk.type'
import { z } from 'zod'

export enum ProofTypes {
  JWT = 'jwt',
}

export const jwtVpJsonHeaderSchema = z.object({
  alg: z.string(),
  typ: z.literal('JWT'),
  kid: z.string().optional(),
})

// RFC 7519 (JWT) registered claim names
export const jwtPayloadBaseSchema = z.object({
  iss: z.string().optional(), // issuer
  sub: z.string().optional(), // subject
  aud: z.union([z.string(), z.array(z.string())]).optional(), // audience
  exp: z.number().optional(), // expiration time
  nbf: z.number().optional(), // not before
  iat: z.number().optional(), // issued at
  jti: z.string().optional(), // JWT ID
})

export const jwtVpJsonPayloadSchema = <T extends z.ZodType>(t: T) =>
  jwtPayloadBaseSchema.extend({
    vp: verifiablePresentationSchema(t),
    nonce: z.string(),
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

export const tokenStatusListEntrySchema = z.object({
  idx: z.number().int().nonnegative(),
  uri: z.string().url(),
})

// draft-ietf-oauth-status-list-18
export const sdJwtVcStatusSchema = z.object({
  status_list: tokenStatusListEntrySchema.optional(),
})

export const sdJwtPayloadSchema = () =>
  jwtPayloadBaseSchema
    .extend({
      // RFC9901
      _sd: z.array(z.string()).optional(),
      _sd_alg: z.string().optional(),
      cnf: z
        .object({
          jwk: jwkSchema.optional(),
        })
        .optional(),
      // draft-ietf-oauth-sd-jwt-vc-14
      vct: z.string(),
      'vct#integrity': z.string().optional(),
      status: sdJwtVcStatusSchema.optional(),
    })
    .catchall(sdJwtPayloadValueSchema)

export type SdJwtArrayDisclosureDigest = z.infer<typeof sdJwtArrayDisclosureDigestSchema>
export type SdJwtPayloadValue = z.infer<typeof sdJwtPayloadValueSchema>
export type SdJwtPayload = z.infer<ReturnType<typeof sdJwtPayloadSchema>>

export const vpTokenPayloadSchema = <T extends z.ZodType>(t: T) =>
  z.union([jwtVpJsonPayloadSchema(t), sdJwtPayloadSchema()])

export type VpTokenPayload<T extends Record<string, unknown> = Record<string, unknown>> = z.infer<
  ReturnType<typeof vpTokenPayloadSchema<z.ZodType<T>>>
>
