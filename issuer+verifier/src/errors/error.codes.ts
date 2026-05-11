export type ErrorCodes =
  // OAuth 2.0 :: Token Error Response
  //
  // https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
  // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.3
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  | 'invalid_dpop_proof'
  | 'use_dpop_nonce'

  // OID4VCI :: Credential Error Response
  //
  // https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1
  // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.3.1
  | 'invalid_token'
  | 'insufficient_scope'
  | 'invalid_credential_request'
  | 'invalid_proof'
  | 'invalid_nonce'
  | 'invalid_encryption_parameters'
  | 'credential_request_denied'
  | 'unsupported_credential_type'
  | 'unknown_credential_configuration'
  | 'unknown_credential_identifier'

  // OID4VP :: Error Response
  //
  // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4
  | 'access_denied'
  | 'vp_formats_not_supported'
  | 'invalid_presentation_definition_uri'
  | 'invalid_presentation_definition_reference'
  | 'invalid_request_uri_method'
  | 'wallet_unavailable'

  // VCKNOTS :: CLIENT ERROR
  | 'issuer_not_found'
  | 'verifier_not_found'
  | 'credential_configuration_not_found'
  | 'authorization_metadata_not_found'
  | 'offer_not_found'
  | 'invalid_grant'
  | 'duplicate_credential_configuration_name'
  | 'unauthorized'
  | 'forbidden'
  | 'user_not_found'
  | 'issuer_user_already_exists'
  | 'verifier_user_already_exists'
  | 'jwks_not_found'
  | 'invalid_presentation_submission'
  | 'invalid_options'
  | 'invalid_sd_jwt'
  | 'invalid_configuration'

  // VCKNOTS :: SERVER ERROR
  | 'internal_server_error'
  | 'illegal_argument'
  | 'illegal_state'
  | 'unsupported_grant_type'
  | 'provider_not_found'
  | 'issuer_public_key_corrupted'
  | 'issuer_asymmetric_sign_failed'
  | 'unsupported_issuer_key_alg'
  | 'invalid_access_token'
  | 'invalid_issuer_key'
  | 'authz_issuer_key_not_found'
  | 'authz_verifier_key_not_found'
  | 'invalid_credential'
  | 'unsupported_vp_token'
  | 'invalid_vp_token'
  | 'invalid_jwt'
  | 'invalid_claims'
  | 'holder_binding_failed'
  | 'unsupported_client_id_scheme'
  | 'unsupported_proofs_type'
  | 'invalid_certificate'
  | 'duplicate_verifier'
  | 'duplicate_issuer'
  | 'duplicate_authz_server'
  | 'certificate_not_found'
  | 'request_object_not_found'
  | 'verifier_vp_formats_not_supported'
  | 'unsupported_cryptographic_binding_method'
