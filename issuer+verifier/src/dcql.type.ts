import { z } from 'zod'
import { DcqlQuery } from 'dcql'
import { DeepPartialUnknown } from './type.utils'

const dcqlSchema = z.object({
  dcql_query: z.custom<DcqlQuery>((val) => {
    try {
      const parsed = DcqlQuery.parse(val as DcqlQuery.Input)
      DcqlQuery.validate(parsed)
      return true
    } catch {
      return false
    }
  }),
})
export type Dcql = z.infer<typeof dcqlSchema>
export const Dcql = (value?: DeepPartialUnknown<Dcql>) => dcqlSchema.parse(value)
Dcql.schema = dcqlSchema
