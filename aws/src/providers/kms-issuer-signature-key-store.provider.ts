import { IssuerSignatureKeyStoreProvider } from '@trustknots/vcknots/providers'
import { KmsProviderOptions } from './kms'
import { createKmsSignatureKeyStore } from './kms-signature-key-store.factory'

// CreateAlias/UpdateAlias require kms:CreateAlias/kms:UpdateAlias permission on the target
// KMS key itself, not just the alias — and the key's ARN isn't known before CreateKey runs.
// Tagging every key we create lets the CDK stack authorize the key side of those actions
// via an aws:ResourceTag condition instead of a key ARN it can't know in advance.
export const ISSUER_KEY_TAG_KEY = 'vcknots:issuer-signature-key'

export const ISSUER_KEY_ALIAS_PREFIX = 'alias/vcknots/issuers/'

export const kmsIssuerSignatureKeyStore = (
  options?: KmsProviderOptions
): IssuerSignatureKeyStoreProvider => ({
  kind: 'issuer-signature-key-store-provider',
  name: 'kms-issuer-signature-key-store-provider',
  single: true,

  ...createKmsSignatureKeyStore(
    {
      subject: 'issuer',
      aliasPrefix: ISSUER_KEY_ALIAS_PREFIX,
      tagKey: ISSUER_KEY_TAG_KEY,
      keyNotFoundError: 'authz_issuer_key_not_found',
    },
    options
  ),
})
