import { AuthzSignatureKeyStoreProvider } from '@trustknots/vcknots/providers'
import { KmsProviderOptions } from './kms'
import {
  KmsSignatureKeyStoreDefaults,
  createKmsSignatureKeyStore,
} from './kms-signature-key-store.factory'

// CreateAlias/UpdateAlias require kms:CreateAlias/kms:UpdateAlias permission on the target
// KMS key itself, not just the alias — and the key's ARN isn't known before CreateKey runs.
// Tagging every key we create lets the CDK stack authorize the key side of those actions
// via an aws:ResourceTag condition instead of a key ARN it can't know in advance.
export const AUTHZ_KEY_TAG_KEY = 'vcknots:authz-signature-key'

export const AUTHZ_KEY_ALIAS_PREFIX = 'alias/vcknots/authz/'

export const kmsAuthzSignatureKeyStore = (
  options?: KmsProviderOptions
): AuthzSignatureKeyStoreProvider & KmsSignatureKeyStoreDefaults => ({
  kind: 'authz-signature-key-store-provider',
  name: 'kms-authz-signature-key-store-provider',
  single: true,

  ...createKmsSignatureKeyStore(
    {
      subject: 'authorization server',
      aliasPrefix: AUTHZ_KEY_ALIAS_PREFIX,
      tagKey: AUTHZ_KEY_TAG_KEY,
      keyNotFoundError: 'authz_issuer_key_not_found',
    },
    options
  ),
})
