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
 * Zod schema for ClaimDisplay.
 * Display properties for a specific Claim.
 */
const claimDisplaySchema = z.object({
  /**
   * The human-readable name (label) for the claim.
   */
  name: z.string().optional(),

  /**
   * (Optional) String representing the locale of the display information.
   */
  locale: z.string().optional(),
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
   */
  locale: z.string().optional(),

  /**
   * (Optional) URL of the issuer's logo.
   */
  logo: logoDetailsSchema.optional(),

  /**
   * (Optional) A description of the issuer.
   */
  description: z.string().optional(),

  /**
   * (Optional) Background color for the issuer's display card (HEX string).
   */
  background_color: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/, 'Must be a valid HEX color code')
    .optional(),

  background_image: z.string().optional(),

  /**
   * (Optional) Text color for the issuer's display card (HEX string).
   */
  text_color: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/, 'Must be a valid HEX color code')
    .optional(),
})

/**
 * Zod schema for CredentialDisplay.
 * Display properties for a Credential.
 */
const credentialDisplaySchema = z.object({
  /**
   * The name of the credential to be displayed to the end-user.
   */
  name: z.string().optional(),

  /**
   * (Optional) String representing the locale of the display information, e.g., "en-US", "ja-JP".
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
   * (Optional) Background color for the credential's display card (HEX string).
   */
  background_color: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/, 'Must be a valid HEX color code')
    .optional(),

  background_image: z.string().optional(),

  /**
   * (Optional) Text color for the credential's display card (HEX string).
   */
  text_color: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/, 'Must be a valid HEX color code')
    .optional(),

  /**
   * (Optional) Title for the credential display.
   */
  title: z.string().optional(), // As per Credential Manifest spec, could be an object too.

  /**
   * (Optional) Subtitle for the credential display.
   */
  subtitle: z.string().optional(), // As per Credential Manifest spec, could be an object too.
})

/**
 * Zod schema for ClaimDetails.
 * Details about a specific claim within the credentialSubject.
 */
const claimDetailsSchema = z.object({
  /**
   * (Optional) If true, this claim must be present in the credential.
   */
  mandatory: z.boolean().optional(),

  /**
   * (Optional) The data type of the claim, e.g., "string", "number", "date".
   */
  value_type: z.string().optional(),

  /**
   * (Optional) Display properties for this specific claim.
   */
  display: z.array(claimDisplaySchema).optional(),
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
   * (Optional) A JSON object that defines the claims structure within the `credentialSubject`
   * of the Verifiable Credential. Keys are claim names, and values can be objects
   * specifying details like `mandatory` or display properties.
   */
  credentialSubject: z.record(z.string(), claimDetailsSchema).optional(),
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

/**
 * Zod schema for CredentialConfigurationSupported.
 * Describes a supported credential configuration by the Issuer.
 * This is part of `credential_configurations_supported` in `CredentialIssuerMetadata`.
 */
const credentialConfigurationSchema = z.object({
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
   * An object defining the structure and type of the credential.
   */
  credential_definition: credentialDefinitionSchema,

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
   * (Optional) Information about the credential type for display purposes in the wallet.
   */
  display: z.array(credentialDisplaySchema).optional(),

  /**
   * (Optional for VCI spec, but often used) Order of claims.
   * If present, it's an array of claim names specifying the order in which they should be displayed.
   */
  order: z.array(z.string()).optional(),

  /**
   * (Optional) Verifiable Credential Type for dc+sd-jwt format credentials.
   */
  vct: z.string().optional(),
})

const credentialIssuerSchema = z.string().url().brand('CredentialIssuer')

const credentialConfigurationIdSchema = z.string().brand('CredentialConfigurationId')

/**
 * Zod schema for CredentialIssuerMetadata.
 * Represents the metadata of a Credential Issuer.
 * This is typically published at a well-known URI (`/.well-known/openid-credential-issuer`).
 * Based on OpenID for Verifiable Credential Issuance specification.
 */
const credentialIssuerMetadataSchema = z.object({
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
   * (Optional) URL of the Batch Credential Endpoint.
   */
  batch_credential_endpoint: z.string().url().optional(),

  /**
   * (Optional) URL of the Deferred Credential Endpoint.
   */
  deferred_credential_endpoint: z.string().url().optional(),

  /**
   * (Optional) A JSON array of strings representing supported JWA [RFC7518]
   * encryption algorithm (alg values) for encrypting credential responses.
   */
  credential_response_encryption_alg_values_supported: z.array(z.string()).optional(),

  /**
   * (Optional) A JSON array of strings representing supported JWA [RFC7518]
   * encryption algorithm (enc values) for encrypting credential responses.
   */
  credential_response_encryption_enc_values_supported: z.array(z.string()).optional(),

  /**
   * (Optional) Boolean value specifying whether the issuer requires credential
   * responses to be encrypted. Default is false.
   */
  require_credential_response_encryption: z.boolean().optional(),

  /**
   * (Optional) A JSON object map where keys are credential configuration IDs
   * and values are objects containing metadata about the supported credential type.
   * This effectively replaces or complements `credential_manifest_uri`.
   * fix
   * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-issuer-metadata-p
   * REQUIRED. Object that describes specifics of the Credential that the Credential Issuer supports issuance of.
   */
  credential_configurations_supported: z.record(z.string(), credentialConfigurationSchema),
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

export type CredentialConfigurationId = z.infer<typeof credentialConfigurationIdSchema>

export type CredentialIssuer = z.infer<typeof credentialIssuerSchema>
export type CredentialIssuerMetadata = z.infer<typeof credentialIssuerMetadataSchema>
export type CredentialConfiguration = z.infer<typeof credentialConfigurationSchema>
export type CredentialDefinition = z.infer<typeof credentialDefinitionSchema>
export type ClaimDetails = z.infer<typeof claimDetailsSchema>
export type IssuerDisplay = z.infer<typeof issuerDisplaySchema>
export type CredentialDisplay = z.infer<typeof credentialDisplaySchema>
export type ClaimDisplay = z.infer<typeof claimDisplaySchema>
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
  batch_credential_endpoint?: string
  deferred_credential_endpoint?: string
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
        type?: string[]
        credentialSubject?: {
          [key: string]: {
            mandatory?: boolean
            value_type?: string
            display?: { name?: string; locale?: string }[]
          }
        }
      }
      proof_types_supported?: {
        [key: string]: {
          proof_signing_alg_values_supported: string[]
        }
      }
      credential_signing_alg_values_supported?: string[]
      display?: {
        name?: string
        locale?: string
        logo?: {
          uri?: string
          alt_text?: string
        }
        description?: string
        background_color?: string
        background_image?: string
        text_color?: string
      }[]
      order?: string[]
    }
  }
  credential_manifest_uri?: string
  display?: {
    name?: string
    locale?: string
    logo?: {
      uri?: string
      alt_text?: string
    }
    description?: string
    background_color?: string
    text_color?: string
  }[]
}) => credentialIssuerMetadataSchema.parse(value)
