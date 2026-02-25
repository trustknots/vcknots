import { VcknotsError } from '@trustknots/vcknots/errors'

export const handleError = (err: unknown) => {
  console.error(err)
  if (err instanceof VcknotsError) {
    return { error: err.name, error_description: err.message }
  }
  if (err instanceof Error) {
    return { error: 'internal_server_error', error_description: err.message }
  }
  return { error: 'internal_server_error', error_description: 'An unexpected error occurred' }
}
