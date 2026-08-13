import { Construct } from 'constructs';
import { DataStores } from '../data/data-stores';
import { grantSignatureKeyStoreAccess } from '../security/signature-key-policy';
import { LambdaApi } from './lambda-api';

// Both values must match aws/src/providers/kms-verifier-signature-key-store.provider.ts. They are
// matched against the alias and tag the provider attaches at runtime, so a mismatch is not caught
// at build time — it surfaces as AccessDenied from KMS after deploy.
const VERIFIER_KEY_ALIAS_PREFIX = 'alias/vcknots/verifiers/';
const VERIFIER_KEY_TAG_KEY = 'vcknots:verifier-signature-key';

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

    // The verifier creates and uses JAR signing keys at runtime (kmsVerifierSignatureKeyStore).
    grantSignatureKeyStoreAccess(this, this.lambdaApi.role, {
      aliasPrefix: VERIFIER_KEY_ALIAS_PREFIX,
      tagKey: VERIFIER_KEY_TAG_KEY,
    });
  }
}
