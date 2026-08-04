import { Construct } from 'constructs';
import { Stack } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { DataStores } from '../data/data-stores';
import { LambdaApi } from './lambda-api';

const ISSUER_KEY_ALIAS_PREFIX = 'alias/vcknots/issuers/';

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
    this.lambdaApi.role.addToPolicy(
      new iam.PolicyStatement({
        actions: ['kms:CreateKey'],
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

    // Alias create/update is scoped to the issuer's alias namespace.
    this.lambdaApi.role.addToPolicy(
      new iam.PolicyStatement({
        actions: ['kms:CreateAlias', 'kms:UpdateAlias'],
        resources: [issuerKeyAliasArn],
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
