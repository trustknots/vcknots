import { z } from 'zod'

const credentialSchema = z.object({
  credential: z.string(),
})

const credentialResponseSchema = z.object({
  // string for JWT
  credentials: z.array(credentialSchema).optional(),
  transaction_id: z.string().optional(),
  interval: z.number().optional(),
  notification_id: z.string().optional(),
})
export type CredentialResponse = z.infer<typeof credentialResponseSchema>
