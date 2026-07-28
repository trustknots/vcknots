import { z } from 'zod'
import { Dcql } from './dcql.type'

const transactionIdSchema = z.string().brand('TransactionId')

const transactionSchema = z.object({
  transaction_id: transactionIdSchema,
  dcqlQuery: Dcql.schema,
  transaction_data_expires_at: z.number(),
})

const transactionRecordSchema = z.object({
  dcqlQuery: Dcql.schema,
})

export type TransactionId = z.infer<typeof transactionIdSchema>
export const TransactionId = (value?: string) => transactionIdSchema.parse(value)
TransactionId.schema = transactionIdSchema

export type Transaction = z.infer<typeof transactionSchema>
export const Transaction = (value?: Transaction) => transactionSchema.parse(value)
Transaction.schema = transactionSchema

export type TransactionRecord = z.infer<typeof transactionRecordSchema>
export const TransactionRecord = (value?: TransactionRecord) => transactionRecordSchema.parse(value)
TransactionRecord.schema = transactionRecordSchema
