import z from 'zod'

export const jwkSchema = z
  .looseObject({
    e: z.string().optional(),
    n: z.string().optional(),
    kty: z.string().optional(),
    x: z.string().optional(),
    y: z.string().optional(),
    crv: z.string().optional(),
    kid: z.string().optional(),
    use: z.string().optional(),
    alg: z.string().optional(),
  })
  .catchall(z.unknown())

export const jwkSetSchema = z.object({
  keys: z.array(jwkSchema),
})

export type Jwk = z.infer<typeof jwkSchema>
export type JwkSet = z.infer<typeof jwkSetSchema>
