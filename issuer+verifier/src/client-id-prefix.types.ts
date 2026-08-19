import { z } from 'zod'

// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3
export const ClientIdPrefixSchema = z.enum([
  'redirect_uri',
  'openid_federation',
  'decentralized_identifier',
  'verifier_attestation',
  'x509_san_dns',
  'x509_hash',
  'origin',
])

export type ClientIdPrefix = z.infer<typeof ClientIdPrefixSchema>
export const ClientIdPrefix = (value?: unknown) => ClientIdPrefixSchema.parse(value)
ClientIdPrefix.schema = ClientIdPrefixSchema
export type ClientIdentifier = `${ClientIdPrefix}:${string}`
const prefixAlternation = ClientIdPrefixSchema.options
  .map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  .join('|')
const re = new RegExp(`^(?:${prefixAlternation}):.+$`)

const ClientIdentifierSchema = z
  .string()
  .regex(re, 'Invalid client identifier')
  .transform((v): ClientIdentifier => v as ClientIdentifier)
export const ClientIdentifier = (value?: unknown): ClientIdentifier =>
  ClientIdentifierSchema.parse(value)
ClientIdentifier.schema = ClientIdentifierSchema
