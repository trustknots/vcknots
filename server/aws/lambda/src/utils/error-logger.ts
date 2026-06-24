export type SanitizedError = {
	message: string
	name?: string
	stack?: string
}

export function sanitizeError(err: unknown): SanitizedError {
	if (err instanceof Error) {
		return {
			message: err.message,
			name: err.name,
			stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
		}
	}
	return { message: 'Unknown error' }
}
