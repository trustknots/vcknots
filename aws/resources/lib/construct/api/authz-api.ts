import { Construct } from 'constructs';
import { DataStores } from '../data/data-stores';
import { LambdaApi } from './lambda-api';

export class AuthzApi extends Construct {
  public readonly lambdaApi: LambdaApi;

  constructor(scope: Construct, id: string, dataStores: DataStores) {
    super(scope, id);

    this.lambdaApi = new LambdaApi(this, 'Api', {
      handlerFile: 'authz.ts',
      restApiName: 'vcknots-authz',
      logGroupName: '/vcknots/authz',
      readWriteTables: [dataStores.authServersTable, dataStores.preCodesTable],
      environment: {
        AUTH_SERVERS_TABLE_NAME: dataStores.authServersTable.tableName,
        PRE_CODES_TABLE_NAME: dataStores.preCodesTable.tableName,
      },
    });
  }
}
