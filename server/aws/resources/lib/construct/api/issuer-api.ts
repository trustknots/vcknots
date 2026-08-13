import { Construct } from 'constructs';
import { DataStores } from '../data/data-stores';
import { grantSignatureKeyStoreAccess } from '../security/signature-key-policy';
import { LambdaApi, requiredEnv } from './lambda-api';

// Both values must match aws/src/providers/kms-issuer-signature-key-store.provider.ts. They are
// matched against the alias and tag the provider attaches at runtime, so a mismatch is not caught
// at build time — it surfaces as AccessDenied from KMS after deploy.
const ISSUER_KEY_ALIAS_PREFIX = 'alias/vcknots/issuers/';
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
        TX_CODE_PEPPER: requiredEnv('TX_CODE_PEPPER'),
      },
    });

    // The issuer creates and uses signing keys at runtime (kmsIssuerSignatureKeyStore).
    grantSignatureKeyStoreAccess(this, this.lambdaApi.role, {
      aliasPrefix: ISSUER_KEY_ALIAS_PREFIX,
      tagKey: ISSUER_KEY_TAG_KEY,
    });
  }
}
