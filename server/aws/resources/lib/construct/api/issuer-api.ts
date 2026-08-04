import { Construct } from 'constructs';
import { Stack } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { DataStores } from '../data/data-stores';
import { LambdaApi } from './lambda-api';

const ISSUER_KEY_ALIAS_PREFIX = 'alias/vcknots/issuers/';
// Must match ISSUER_KEY_TAG_KEY in aws/src/providers/kms-issuer-signature-key-store.provider.ts.
const ISSUER_KEY_TAG_KEY = 'vcknots:issuer-signature-key';

export class IssuerApi extends Construct {
  public readonly lambdaApi: LambdaApi;

  constructor(scope: Construct, id: string, dataStores: DataStores) {
    super(scope, id);

    this.lambdaApi = new LambdaApi(this, 'Api', {
      handlerFile: 'issuer.ts',
      serviceName: 'issuer',
      readWriteTables: [dataStores.issuersTable, dataStores.noncesTable],
      writeOnlyTables: [dataStores.preCodesTable],
      environment: {
        ISSUERS_TABLE_NAME: dataStores.issuersTable.tableName,
        NONCES_TABLE_NAME: dataStores.noncesTable.tableName,
        PRE_CODES_TABLE_NAME: dataStores.preCodesTable.tableName,
      },
    });

    // The issuer creates and uses signing keys at runtime (kmsIssuerSignatureKeyStore),
    // so keys cannot be provisioned here and referenced by ARN.
    const stack = Stack.of(this);
    const issuerKeyAliasArn = `arn:${stack.partition}:kms:${stack.region}:${stack.account}:${ISSUER_KEY_ALIAS_PREFIX}*`;

    // kms:CreateKey has no target resource yet, so IAM requires Resource "*" for it.
    // Conditions pin the request to the KeyUsage/KeySpec/Origin combinations the
    // provider actually creates (see aws/src/providers/kms-provider.utils.ts),
    // so a compromised Lambda can't mint unrelated key types under this role.
    // kms:TagResource is required alongside CreateKey because the provider tags every
    // key it creates (see below for why).
    this.lambdaApi.role.addToPolicy(
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
    // the key). The alias side is scoped to the issuer's alias namespace here...
    this.lambdaApi.role.addToPolicy(
      new iam.PolicyStatement({
        actions: ['kms:CreateAlias', 'kms:UpdateAlias'],
        resources: [issuerKeyAliasArn],
      }),
    );

    // ...and the key side is authorized via the tag the provider sets on every key it
    // creates (see ISSUER_KEY_TAG_KEY above), since a brand-new key has no alias yet for
    // kms:ResourceAliases to match on the first CreateAlias call.
    this.lambdaApi.role.addToPolicy(
      new iam.PolicyStatement({
        actions: ['kms:CreateAlias', 'kms:UpdateAlias'],
        resources: ['*'],
        conditions: {
          StringEquals: {
            [`aws:ResourceTag/${ISSUER_KEY_TAG_KEY}`]: 'true',
          },
        },
      }),
    );

    // Key-level actions target the key by alias at call time (no ARN available here),
    // so Resource stays "*" and access is narrowed via the kms:ResourceAliases condition
    // to keys carrying an alias/vcknots/issuers/* alias.
    this.lambdaApi.role.addToPolicy(
      new iam.PolicyStatement({
        actions: [
          'kms:DescribeKey',
          'kms:GetPublicKey',
          'kms:Sign',
          'kms:GetParametersForImport',
          'kms:ImportKeyMaterial',
          'kms:ScheduleKeyDeletion',
        ],
        resources: ['*'],
        conditions: {
          'ForAnyValue:StringLike': {
            'kms:ResourceAliases': `${ISSUER_KEY_ALIAS_PREFIX}*`,
          },
        },
      }),
    );
  }
}
