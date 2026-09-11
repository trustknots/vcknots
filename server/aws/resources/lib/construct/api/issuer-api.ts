import { Construct } from 'constructs';
import { DataStores } from '../data/data-stores';
import {
  grantSignatureKeyPublicKeyAccess,
  grantSignatureKeyStoreAccess,
} from '../security/signature-key-policy';
import { AuthzApi } from './authz-api';
import { LambdaApi, requiredEnv } from './lambda-api';

// Both values must match aws/src/providers/kms-issuer-signature-key-store.provider.ts. They are
// matched against the alias and tag the provider attaches at runtime, so a mismatch is not caught
// at build time — it surfaces as AccessDenied from KMS after deploy.
const ISSUER_KEY_ALIAS_PREFIX = 'alias/vcknots/issuers/';
const ISSUER_KEY_TAG_KEY = 'vcknots:issuer-signature-key';

// Must match aws/src/providers/kms-authz-signature-key-store.provider.ts (and authz-api.ts).
const AUTHZ_KEY_ALIAS_PREFIX = 'alias/vcknots/authz/';

export class IssuerApi extends Construct {
  public readonly lambdaApi: LambdaApi;

  constructor(scope: Construct, id: string, dataStores: DataStores, authzApi: AuthzApi) {
    super(scope, id);

    this.lambdaApi = new LambdaApi(this, 'Api', {
      handlerFile: 'issuer.ts',
      serviceName: 'issuer',
      readWriteTables: [dataStores.issuersTable, dataStores.noncesTable],
      writeOnlyTables: [dataStores.preCodesTable],
      environment: {
        // Match the token issuer from getBaseUrl(), which has no trailing slash.
        AUTHZ_BASE_URL: authzApi.lambdaApi.restApi.url.replace(/\/$/, ''),
        ISSUERS_TABLE_NAME: dataStores.issuersTable.tableName,
        NONCES_TABLE_NAME: dataStores.noncesTable.tableName,
        PRE_CODES_TABLE_NAME: dataStores.preCodesTable.tableName,
        AUTHZ_OAUTH_CLIENTS_TABLE_NAME: dataStores.authzOAuthClientsTable.tableName,
        AUTHZ_OAUTH_POLICIES_TABLE_NAME: dataStores.authzOAuthPoliciesTable.tableName,
        TX_CODE_PEPPER: requiredEnv('TX_CODE_PEPPER'),
      },
    });

    // Credential / nonce endpoints resolve DPoP mode and registered clients from the same
    // tables Authz writes. Issuer only needs to read them.
    dataStores.authzOAuthClientsTable.grantReadData(this.lambdaApi.role);
    dataStores.authzOAuthPoliciesTable.grantReadData(this.lambdaApi.role);

    // The issuer creates and uses signing keys at runtime (kmsIssuerSignatureKeyStore).
    grantSignatureKeyStoreAccess(this, this.lambdaApi.role, {
      aliasPrefix: ISSUER_KEY_ALIAS_PREFIX,
      tagKey: ISSUER_KEY_TAG_KEY,
    });

    // Credential endpoint verifies Authz-issued access tokens. Read the Authz public
    // key only — CreateKey / Sign on this namespace stay on the Authz role.
    grantSignatureKeyPublicKeyAccess(this, this.lambdaApi.role, AUTHZ_KEY_ALIAS_PREFIX);
  }
}
