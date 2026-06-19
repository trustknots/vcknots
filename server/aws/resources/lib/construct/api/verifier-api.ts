import { Construct } from 'constructs';
import { DataStores } from '../data/data-stores';
import { LambdaApi } from './lambda-api';

export class VerifierApi extends Construct {
  public readonly lambdaApi: LambdaApi;

  constructor(scope: Construct, id: string, dataStores: DataStores) {
    super(scope, id);

    this.lambdaApi = new LambdaApi(this, 'Api', {
      handlerFile: 'verifier.ts',
      serviceName: 'verifier',
      readWriteTables: [
        dataStores.verifiersTable,
        dataStores.requestObjectsTable,
        dataStores.noncesTable,
      ],
      environment: {
        VERIFIERS_TABLE_NAME: dataStores.verifiersTable.tableName,
        REQUEST_OBJECTS_TABLE_NAME: dataStores.requestObjectsTable.tableName,
        NONCES_TABLE_NAME: dataStores.noncesTable.tableName,
      },
    });
  }
}
