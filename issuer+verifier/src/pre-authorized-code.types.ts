import { z } from 'zod'
import { DeepPartialUnknown } from './type.utils'

const preAuthorizedCodeSchema = z.string().brand('PreAuthorizedCode')

const preAuthorizedCodeStoreEntrySchema = z.object({
  code: preAuthorizedCodeSchema,
  tx_code: z.union([z.string(), z.number()]).optional(),
  tx_code_input_mode: z.enum(['numeric', 'text']).optional(),
  expires_at: z.number().optional(),
})
export type PreAuthorizedCode = z.infer<typeof preAuthorizedCodeSchema>
export type PreAuthorizedCodeStoreEntry = z.infer<typeof preAuthorizedCodeStoreEntrySchema>
export const PreAuthorizedCode = (value?: string) => preAuthorizedCodeSchema.parse(value)
PreAuthorizedCode.schema = preAuthorizedCodeSchema
export const PreAuthorizedCodeStoreEntry = (
  value?: DeepPartialUnknown<PreAuthorizedCodeStoreEntry>
) => preAuthorizedCodeStoreEntrySchema.parse(value)
PreAuthorizedCodeStoreEntry.schema = preAuthorizedCodeStoreEntrySchema
