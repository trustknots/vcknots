import { z } from 'zod'

export const kbJwtJsonPayloadSchema = z.object({
  iat: z.number(),
  aud: z.string(),
  nonce: z.string(),
  sd_hash: z.string(),
})

export const kbJwtJsonHeaderSchema = z.object({
  alg: z.string(),
  typ: z.literal('kb+jwt'),
})

export type KbJwtJsonPayload = z.infer<typeof kbJwtJsonPayloadSchema>
export type JKbJwtJsonHeader = z.infer<typeof kbJwtJsonHeaderSchema>

export const KbJwtJsonPayload = (value?: KbJwtJsonPayload) => kbJwtJsonPayloadSchema.parse(value)
export const JKbJwtJsonHeader = (value?: JKbJwtJsonHeader) => kbJwtJsonHeaderSchema.parse(value)
