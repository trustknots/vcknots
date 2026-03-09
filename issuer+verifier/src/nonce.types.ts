import { z } from 'zod'

const nonceSchema = z.string().brand('Nonce')

export type Nonce = z.infer<typeof nonceSchema>
export const Nonce = (value?: string) => nonceSchema.parse(value)
Nonce.schema = nonceSchema
