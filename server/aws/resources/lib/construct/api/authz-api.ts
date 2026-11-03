import { Construct } from 'constructs';
import { DataStores } from '../data/data-stores';
import { grantSignatureKeyStoreAccess } from '../security/signature-key-policy';
import { LambdaApi, requiredEnv } from './lambda-api';

// Both values must match aws/src/providers/kms-authz-signature-key-store.provider.ts. They are
// matched against the alias and tag the provider attaches at runtime, so a mismatch is not caught
// at build time — it surfaces as AccessDenied from KMS after deploy.
const AUTHZ_KEY_ALIAS_PREFIX = 'alias/vcknots/authz/';
const AUTHZ_KEY_TAG_KEY = 'vcknots:authz-signature-key';

export class AuthzApi extends Construct {
  public readonly lambdaApi: LambdaApi;

  constructor(scope: Construct, id: string, dataStores: DataStores) {
    super(scope, id);

    this.lambdaApi = new LambdaApi(this, 'Api', {
      handlerFile: 'authz.ts',
      serviceName: 'authz',
      readWriteTables: [
        dataStores.authServersTable,
        dataStores.preCodesTable,
        // DPoP nonces issued by /token (use_dpop_nonce) must be visible to every Lambda instance.
        dataStores.noncesTable,
        dataStores.authzOAuthClientsTable,
        dataStores.authzOAuthPoliciesTable,
        dataStores.allowedCredentialConfigurationsTable,
      ],
      environment: {
        AUTH_SERVERS_TABLE_NAME: dataStores.authServersTable.tableName,
        PRE_CODES_TABLE_NAME: dataStores.preCodesTable.tableName,
        NONCES_TABLE_NAME: dataStores.noncesTable.tableName,
        AUTHZ_OAUTH_CLIENTS_TABLE_NAME: dataStores.authzOAuthClientsTable.tableName,
        AUTHZ_OAUTH_POLICIES_TABLE_NAME: dataStores.authzOAuthPoliciesTable.tableName,
        ALLOWED_CREDENTIAL_CONFIGURATIONS_TABLE_NAME:
          dataStores.allowedCredentialConfigurationsTable.tableName,
        DPOP_PROOF_JTIS_TABLE_NAME: dataStores.dpopProofJtisTable.tableName,
        OAUTH_CLIENT_ASSERTION_JTIS_TABLE_NAME: dataStores.oauthClientAssertionJtisTable.tableName,
        TX_CODE_PEPPER: requiredEnv('TX_CODE_PEPPER'),
      },
    });

    // Token endpoint rejects replayed DPoP proofs with a conditional put; no read is needed.
    dataStores.dpopProofJtisTable.grant(this.lambdaApi.role, 'dynamodb:PutItem');

    // Token endpoint rejects replayed client assertions with a conditional put; no read is needed.
    dataStores.oauthClientAssertionJtisTable.grant(this.lambdaApi.role, 'dynamodb:PutItem');

    // The authz server creates and uses its access-token signing key at runtime
    // (kmsAuthzSignatureKeyStore).
    grantSignatureKeyStoreAccess(this, this.lambdaApi.role, {
      aliasPrefix: AUTHZ_KEY_ALIAS_PREFIX,
      tagKey: AUTHZ_KEY_TAG_KEY,
    });
  }
}
