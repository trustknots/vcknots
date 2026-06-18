import { z } from 'zod'
import { type DcqlQuery } from 'dcql'
import { DeepPartialUnknown } from './type.utils'

const dcqlSchema = z.object({
  dcql_query: z.custom<DcqlQuery>(),
})
export type Dcql = z.infer<typeof dcqlSchema>
export const Dcql = (value?: DeepPartialUnknown<Dcql>) => dcqlSchema.parse(value)
Dcql.schema = dcqlSchema
