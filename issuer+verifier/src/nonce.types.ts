import { z } from 'zod'
import { DeepPartialUnknown } from './type.utils'

const nonceSchema = z.object({
  nonce: z.string(),
  nonce_expires_in: z.number().optional(),
})
export type Nonce = z.infer<typeof nonceSchema>
export const Nonce = (value?: DeepPartialUnknown<Nonce>) => nonceSchema.parse(value)
Nonce.schema = nonceSchema
