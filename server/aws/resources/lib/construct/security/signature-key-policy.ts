import { Stack } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface SignatureKeyStorePolicyProps {
  /** KMS alias namespace the store owns, e.g. 'alias/vcknots/issuers/'. */
  aliasPrefix: string;
  /** Tag the provider sets on every key it creates. */
  tagKey: string;
}

/**
 * Grants a Lambda role the KMS permissions a vcknots signature key store needs.
 *
 * The issuer and verifier stores are built from the same provider factory
 * (aws/src/providers/kms-signature-key-store.factory.ts) and issue the same KMS calls, so both
 * roles get the same four statements — only the alias namespace and key tag differ.
 *
 * Keys are created and used at runtime, so they cannot be provisioned here and referenced by ARN.
 */
export function grantSignatureKeyStoreAccess(
  scope: Construct,
  role: iam.IRole,
  props: SignatureKeyStorePolicyProps,
): void {
  const { aliasPrefix, tagKey } = props;
  const stack = Stack.of(scope);
  const keyAliasArn = `arn:${stack.partition}:kms:${stack.region}:${stack.account}:${aliasPrefix}*`;

  // kms:CreateKey has no target resource yet, so IAM requires Resource "*" for it.
  // Conditions pin the request to the KeyUsage/KeySpec/Origin combinations the
  // provider actually creates (see aws/src/providers/kms-provider.utils.ts),
  // so a compromised Lambda can't mint unrelated key types under this role.
  // kms:TagResource is required alongside CreateKey because the provider tags every
  // key it creates (see below for why).
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      actions: ['kms:CreateKey', 'kms:TagResource'],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'kms:KeyUsage': 'SIGN_VERIFY',
          'kms:KeySpec': ['ECC_NIST_P256', 'ECC_NIST_P384', 'RSA_2048', 'RSA_4096'],
          'kms:KeyOrigin': ['AWS_KMS', 'EXTERNAL'],
        },
      },
    }),
  );

  // CreateAlias/UpdateAlias require kms:CreateAlias/kms:UpdateAlias permission on BOTH
  // the alias and the target KMS key (a Resource scoped to the alias ARN does not cover
  // the key). The alias side is scoped to this store's alias namespace here...
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      actions: ['kms:CreateAlias', 'kms:UpdateAlias'],
      resources: [keyAliasArn],
    }),
  );

  // ...and the key side is authorized via the tag the provider sets on every key it
  // creates, since a brand-new key has no alias yet for kms:ResourceAliases to match
  // on the first CreateAlias call.
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      actions: ['kms:CreateAlias', 'kms:UpdateAlias'],
      resources: ['*'],
      conditions: {
        StringEquals: {
          [`aws:ResourceTag/${tagKey}`]: 'true',
        },
      },
    }),
  );

  // Key-level actions target the key by alias at call time (no ARN available here),
  // so Resource stays "*" and access is narrowed via the kms:ResourceAliases condition
  // to keys carrying an alias from this store's namespace.
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      actions: ['kms:DescribeKey', 'kms:GetPublicKey', 'kms:Sign'],
      resources: ['*'],
      conditions: {
        'ForAnyValue:StringLike': {
          'kms:ResourceAliases': `${aliasPrefix}*`,
        },
      },
    }),
  );

  // kms:ResourceAliases matches on the aliases a key already carries, so it can never authorize
  // an action on a key that has no alias yet. The provider imports key material and discards
  // orphan keys before (or instead of) the first CreateAlias, so those calls are scoped by the
  // creation tag instead — the same reason the CreateAlias key-side statement above uses it.
  role.addToPrincipalPolicy(
    new iam.PolicyStatement({
      actions: ['kms:GetParametersForImport', 'kms:ImportKeyMaterial', 'kms:ScheduleKeyDeletion'],
      resources: ['*'],
      conditions: {
        StringEquals: {
          [`aws:ResourceTag/${tagKey}`]: 'true',
        },
      },
    }),
  );
}
