import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import { DataStores } from '../data/data-stores';
import { LambdaApi } from './lambda-api';

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
    // so keys cannot be provisioned here and referenced by ARN. kms:CreateKey only
    // supports Resource "*"; the key-level actions could later be narrowed with an
    // aws:RequestTag / kms:RequestAlias condition once alias-based scoping is needed.
    this.lambdaApi.role.addToPolicy(
      new iam.PolicyStatement({
        actions: [
          'kms:CreateKey',
          'kms:CreateAlias',
          'kms:UpdateAlias',
          'kms:DescribeKey',
          'kms:GetPublicKey',
          'kms:Sign',
          'kms:GetParametersForImport',
          'kms:ImportKeyMaterial',
          'kms:ScheduleKeyDeletion',
        ],
        resources: ['*'],
      }),
    );
  }
}
