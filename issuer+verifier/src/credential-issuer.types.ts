import { z } from 'zod'

/**
 * Zod schema for LogoDetails.
 * Details for a logo image.
 */
const logoDetailsSchema = z.object({
  /**
   * URL of the logo image.
   */
  uri: z.string().url(),

  /**
   * (Optional) Alternative text for the logo image.
   */
  alt_text: z.string().optional(),
})

/**
 * Zod schema for IssuerDisplay.
 * Display properties for an Issuer.
 */
const issuerDisplaySchema = z.object({
  /**
   * The name of the issuer to be displayed to the end-user.
   */
  name: z.string().optional(),

  /**
   * (Optional) String representing the locale of the display information, e.g., "en-US", "ja-JP".
   * MUST be only one object for each language identifier
   */
  locale: z.string().optional(),

  /**
   * (Optional) URL of the issuer's logo.
   */
  logo: logoDetailsSchema.optional(),
})

const credentialMetadataBackgroundImageSchema = z.object({
  /**
   * URL of the background image.
   */
  uri: z.string().url(),
})

/**
 * Zod schema for CredentialMetadataDisplay.
 * Default display properties for a Credential inside credential_metadata.
 */
const credentialMetadataDisplaySchema = z.object({
  /**
   * The display name of the credential.
   */
  name: z.string(),

  /**
   * (Optional) Locale for the display metadata.
   * MUST be only one object for each language identifier.
   */
  locale: z.string().optional(),

  /**
   * (Optional) URL of the credential's logo.
   */
  logo: logoDetailsSchema.optional(),

  /**
   * (Optional) A description of the credential.
   */
  description: z.string().optional(),

  /**
   * (Optional) Background color for the credential display card (HEX string).
   */
  background_color: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/, 'Must be a valid HEX color code')
    .optional(),

  /**
   * (Optional) Background image for the credential display card.
   */
  background_image: credentialMetadataBackgroundImageSchema.optional(),

  /**
   * (Optional) Text color for the credential display card (HEX string).
   */
  text_color: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/, 'Must be a valid HEX color code')
    .optional(),
})

/**
 * Zod schema for CredentialMetadataClaimDisplay.
 * Display properties for a claim in credential_metadata.
 */
const credentialMetadataClaimDisplaySchema = z.object({
  /**
   * (Optional) The display name of the claim.
   */
  name: z.string().optional(),

  /**
   * (Optional) Locale for the claim display metadata.
   * MUST be only one object for each language identifier.
   */
  locale: z.string().optional(),
})

/**
 * Zod schema for CredentialMetadataClaim.
 * Describes how a claim in the credential is displayed to the end-user.
 */
const credentialMetadataClaimSchema = z.object({
  /**
   * A non-empty claims path pointer array that specifies the claim path in the credential.
   */
  path: z.array(z.string()).nonempty(),

  /**
   * (Optional) Indicates whether the issuer always includes this claim.
   */
  mandatory: z.boolean().optional(),

  /**
   * (Optional) Localized display metadata for the claim.
   */
  display: z.array(credentialMetadataClaimDisplaySchema).nonempty().optional(),
})

/**
 * Zod schema for CredentialMetadata.
 * Metadata relevant to the usage and display of issued credentials.
 */
const credentialMetadataSchema = z.object({
  /**
   * (Optional) Localized display metadata for the credential.
   */
  display: z.array(credentialMetadataDisplaySchema).nonempty().optional(),

  /**
   * (Optional) Claim description objects used in issuer metadata.
   */
  claims: z.array(credentialMetadataClaimSchema).nonempty().optional(),
})

/**
 * Zod schema for CredentialDefinition.
 * Defines the type and claims of a credential.
 */
const credentialDefinitionSchema = z.object({
  /**
   * An array of strings, where each string is a URI identifying the type of the credential.
   * The first URI is the primary type. E.g., ["VerifiableCredential", "UniversityDegreeCredential"].
   */
  type: z.array(z.string()).nonempty(),

  /**
   * An array of URIs representing the contexts of the credential, as per W3C Verifiable Credentials specification.
   * the first item is a URI with the value https://www.w3.org/2018/credentials/v1
   * for Credential Format Identifier is ldp_vc
   */
  '@context': z.array(z.string()).optional(),
})

/**
 * Zod schema for ProofTypeSupported.
 * Defines the supported proof types and their associated signing algorithms.
 */
const proofTypeSupportedSchema = z.object({
  /**
   * An array of JWA [RFC7515] algorithm [JWA] values supported for proof signing.
   * E.g., ["ES256", "ES384"].
   */
  proof_signing_alg_values_supported: z.array(z.string()),
})

const encryptionJwkSchema = z
  .object({
    kid: z.string(),
  })
  .and(z.record(z.string(), z.unknown()))

const encryptionJwksSchema = z.object({
  keys: z.array(encryptionJwkSchema).nonempty(),
})

const credentialRequestEncryptionSchema = z.object({
  /**
   * Public keys used by the wallet for request encryption key agreement.
   */
  jwks: encryptionJwksSchema,

  /**
   * Supported JWE enc values for encrypted credential requests.
   */
  enc_values_supported: z.array(z.string()).nonempty(),

  /**
   * Supported JWE zip values for encrypted credential requests.
   */
  zip_values_supported: z.array(z.string()).nonempty().optional(),

  /**
   * Whether encryption is required for every credential request.
   */
  encryption_required: z.boolean(),
})

const credentialResponseEncryptionSchema = z.object({
  /**
   * Supported JWE alg values for encrypted credential responses.
   */
  alg_values_supported: z.array(z.string()).nonempty(),

  /**
   * Supported JWE enc values for encrypted credential responses.
   */
  enc_values_supported: z.array(z.string()).nonempty(),

  /**
   * Supported JWE zip values for encrypted credential responses.
   */
  zip_values_supported: z.array(z.string()).nonempty().optional(),

  /**
   * Whether encryption is required for every credential response.
   */
  encryption_required: z.boolean(),
})

const batchCredentialIssuanceSchema = z.object({
  /**
   * Maximum supported proofs array size for a batch request.
   */
  batch_size: z.number().int().min(2),
})

/**
 * Zod schema for CredentialConfigurationSupported.
 * Describes a supported credential configuration by the Issuer.
 * This is part of `credential_configurations_supported` in `CredentialIssuerMetadata`.
 */
const credentialConfigurationSupportedSchema = z.object({
  /**
   * The format of the credential, e.g., "jwt_vc_json", "ldp_vc".
   * Can also be an array of supported formats.
   */
  format: z.union([z.string(), z.array(z.string())]),

  /**
   * (Optional) The scope string that the Wallet must use to request this credential.
   */
  scope: z.string().optional(),

  /**
   * (Optional) An array of strings representing supported cryptographic binding methods.
   * E.g., "jwk", "did:example".
   */
  cryptographic_binding_methods_supported: z.array(z.string()).optional(),

  /**
   * (Optional) An array of strings representing cryptographic suites used to sign/prove the credential.
   * E.g., "ES256K", "EdDSA".
   */
  cryptographic_suites_supported: z.array(z.string()).optional(),

  /**
   * (Optional) An object mapping proof types to their supported signing algorithms.
   * E.g., { "jwt": { "proof_signing_alg_values_supported": ["ES256"] } }.
   * If not present, the Wallet must use a proof type appropriate for the credential format.
   */
  proof_types_supported: z.record(z.string(), proofTypeSupportedSchema).optional(),

  /**
   * (Optional) An array of JWA [RFC7515] algorithm [JWA] values supported by the
   * Credential Issuer for signing credentials.
   */
  credential_signing_alg_values_supported: z.array(z.string()).optional(),

  /**
   * (Optional) Metadata relevant to the usage and display of the issued credential.
   */
  credential_metadata: credentialMetadataSchema.optional(),

  /**
   * An object defining the structure and type of the credential.
   * for W3C Verifiable Credentials
   */
  credential_definition: credentialDefinitionSchema.optional(),

  /**
   * String identifying the Credential type
   * for Mobile Documents or mdocs (ISO/IEC 18013)
   */
  doctype: z.string().optional(),

  /**
   * String designating the type of the Credential
   * for IETF SD-JWT VC
   */
  vct: z.string().optional(),
})

const credentialIssuerSchema = z.string().url().brand('CredentialIssuer')

const credentialConfigurationIdSchema = z.string().brand('CredentialConfigurationId')

const validateUniqueLocaleArray = <T extends { locale?: string }>(
  arr: T[] | undefined,
  ctx: z.RefinementCtx,
  path: (string | number)[]
) => {
  if (!arr) return
  const localeList = new Set<string>()
  arr.forEach((item, i) => {
    if (item.locale === undefined) return
    const loc = typeof item.locale === 'string' ? item.locale.trim().toLowerCase() : item.locale
    if (localeList.has(loc)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `duplicate display locale: ${loc}`,
        path: [...path, i, 'locale'],
      })
    }
    localeList.add(loc)
  })
}

/**
 * Zod schema for CredentialIssuerMetadata.
 * Represents the metadata of a Credential Issuer.
 * This is typically published at a well-known URI (`/.well-known/openid-credential-issuer`).
 * Based on OpenID for Verifiable Credential Issuance specification.
 */
const credentialIssuerMetadataSchema = z
  .object({
    /**
     * The issuer's identifier (URL).
     */
    credential_issuer: credentialIssuerSchema,

    /**
     * URL of the issuer's OAuth 2.0 Authorization Server.
     * Required if the issuer uses OAuth 2.0 for authorization.
     */
    authorization_servers: z.array(z.string().url()).optional(),

    /**
     * URL of the Credential Endpoint.
     */
    credential_endpoint: z.string().url(),

    /**
     * URL of the Credential Issuer's Nonce Endpoint.
     */
    nonce_endpoint: z.string().url().optional(),

    /**
     * (Optional) URL of the Deferred Credential Endpoint.
     */
    deferred_credential_endpoint: z.string().url().optional(),

    /**
     * URL of the Credential Issuer's Notification Endpoint
     */
    notification_endpoint: z.string().url().optional(),

    /**
     * (Optional) Information about support for credential request encryption on top of TLS.
     */
    credential_request_encryption: credentialRequestEncryptionSchema.optional(),

    /**
     * (Optional) Information about support for credential response encryption on top of TLS.
     */
    credential_response_encryption: credentialResponseEncryptionSchema.optional(),

    /**
     * (Optional) Information about support for issuing multiple credentials in a single batch.
     */
    batch_credential_issuance: batchCredentialIssuanceSchema.optional(),

    /**
     * (Optional) A JSON object map where keys are credential configuration IDs
     * and values are objects containing metadata about the supported credential type.
     * This effectively replaces or complements `credential_manifest_uri`.
     * fix
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-issuer-metadata-p
     * REQUIRED. Object that describes specifics of the Credential that the Credential Issuer supports issuance of.
     */
    credential_configurations_supported: z.record(
      z.string(),
      credentialConfigurationSupportedSchema
    ),
    // .optional(),

    /**
     * (Optional) URL of the Credential Manifest for this issuer.
     * This manifest contains a list of credential types the issuer can issue.
     */
    credential_manifest_uri: z.string().url().optional(),

    /**
     * (Optional) Information about the issuer for display purposes in the wallet.
     */
    display: z.array(issuerDisplaySchema).optional(),
  })
  .superRefine((data, ctx) => {
    // Validate that issuerDisplay locales are unique
    validateUniqueLocaleArray(data.display, ctx, ['display'])

    for (const [id, config] of Object.entries(data.credential_configurations_supported ?? {})) {
      // Validate that credentialMetadataDisplay locales are unique
      validateUniqueLocaleArray(config.credential_metadata?.display, ctx, [
        'credential_configurations_supported',
        id,
        'credential_metadata',
        'display',
      ])

      // Validate that credentialMetadataClaimDisplay locales are unique
      const claims = config.credential_metadata?.claims ?? []
      claims.forEach((claim, index) => {
        validateUniqueLocaleArray(claim.display, ctx, [
          'credential_configurations_supported',
          id,
          'credential_metadata',
          'claims',
          index,
          'display',
        ])
      })
    }
  })

export type CredentialConfigurationId = z.infer<typeof credentialConfigurationIdSchema>

export type CredentialIssuer = z.infer<typeof credentialIssuerSchema>
export type CredentialIssuerMetadata = z.infer<typeof credentialIssuerMetadataSchema>
export type CredentialConfigurationSupported = z.infer<
  typeof credentialConfigurationSupportedSchema
>
export type CredentialDefinition = z.infer<typeof credentialDefinitionSchema>
export type IssuerDisplay = z.infer<typeof issuerDisplaySchema>
export type CredentialMetadata = z.infer<typeof credentialMetadataSchema>
export type CredentialMetadataDisplay = z.infer<typeof credentialMetadataDisplaySchema>
export type CredentialMetadataClaim = z.infer<typeof credentialMetadataClaimSchema>
export type CredentialMetadataClaimDisplay = z.infer<typeof credentialMetadataClaimDisplaySchema>
export type EncryptionJwk = z.infer<typeof encryptionJwkSchema>
export type EncryptionJwks = z.infer<typeof encryptionJwksSchema>
export type CredentialRequestEncryption = z.infer<typeof credentialRequestEncryptionSchema>
export type CredentialResponseEncryption = z.infer<typeof credentialResponseEncryptionSchema>
export type BatchCredentialIssuance = z.infer<typeof batchCredentialIssuanceSchema>
export type LogoDetails = z.infer<typeof logoDetailsSchema>
export type ProofTypeSupported = z.infer<typeof proofTypeSupportedSchema>

export const CredentialIssuer = (value?: string) => credentialIssuerSchema.parse(value)
CredentialIssuer.schema = credentialIssuerSchema

export const CredentialConfigurationId = (value?: string) =>
  credentialConfigurationIdSchema.parse(value)
CredentialConfigurationId.schema = credentialConfigurationIdSchema

export const CredentialIssuerMetadata = (value?: {
  credential_issuer?: string
  authorization_servers?: string[]
  credential_endpoint?: string
  nonce_endpoint?: string
  deferred_credential_endpoint?: string
  notification_endpoint?: string
  credential_request_encryption?: {
    jwks: {
      keys: ({
        kid: string
      } & Record<string, unknown>)[]
    }
    enc_values_supported: string[]
    zip_values_supported?: string[]
    encryption_required: boolean
  }
  credential_response_encryption?: {
    alg_values_supported: string[]
    enc_values_supported: string[]
    zip_values_supported?: string[]
    encryption_required: boolean
  }
  batch_credential_issuance?: {
    batch_size: number
  }
  credential_response_encryption_alg_values_supported?: string[]
  credential_response_encryption_enc_values_supported?: string[]
  require_credential_response_encryption?: boolean
  credential_configurations_supported?: {
    [key: string]: {
      format?: string | string[]
      scope?: string
      cryptographic_binding_methods_supported?: string[]
      cryptographic_suites_supported?: string[]
      credential_definition?: {
        '@context'?: string[]
        type?: string[]
      }
      doctype?: string
      vct?: string
      proof_types_supported?: {
        [key: string]: {
          proof_signing_alg_values_supported: string[]
        }
      }
      credential_signing_alg_values_supported?: string[]
      credential_metadata?: {
        display?: {
          name: string
          locale?: string
          logo?: {
            uri?: string
            alt_text?: string
          }
          description?: string
          background_color?: string
          background_image?: {
            uri: string
          }
          text_color?: string
        }[]
        claims?: {
          path: string[]
          mandatory?: boolean
          display?: {
            name?: string
            locale?: string
          }[]
        }[]
      }
    }
  }
  display?: {
    name?: string
    locale?: string
    logo?: {
      uri?: string
      alt_text?: string
    }
  }[]
}) => credentialIssuerMetadataSchema.parse(value)
