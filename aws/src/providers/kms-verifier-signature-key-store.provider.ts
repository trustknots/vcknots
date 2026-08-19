import { VerifierSignatureKeyStoreProvider } from '@trustknots/vcknots/providers'
import { KmsProviderOptions } from './kms'
import { createKmsSignatureKeyStore } from './kms-signature-key-store.factory'

// CreateAlias/UpdateAlias require kms:CreateAlias/kms:UpdateAlias permission on the target
// KMS key itself, not just the alias — and the key's ARN isn't known before CreateKey runs.
// Tagging every key we create lets the CDK stack authorize the key side of those actions
// via an aws:ResourceTag condition instead of a key ARN it can't know in advance.
export const VERIFIER_KEY_TAG_KEY = 'vcknots:verifier-signature-key'

export const VERIFIER_KEY_ALIAS_PREFIX = 'alias/vcknots/verifiers/'

export const kmsVerifierSignatureKeyStore = (
  options?: KmsProviderOptions
): VerifierSignatureKeyStoreProvider => ({
  kind: 'verifier-signature-key-store-provider',
  name: 'kms-verifier-signature-key-store-provider',
  single: true,

  ...createKmsSignatureKeyStore(
    {
      subject: 'verifier',
      aliasPrefix: VERIFIER_KEY_ALIAS_PREFIX,
      tagKey: VERIFIER_KEY_TAG_KEY,
      keyNotFoundError: 'authz_verifier_key_not_found',
    },
    options
  ),
})
