import { Construct } from 'constructs';
import { Stack } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { DataStores } from '../data/data-stores';
import { grantSignatureKeyStoreAccess } from '../security/signature-key-policy';
import { LambdaApi } from './lambda-api';

// Both values must match aws/src/providers/kms-verifier-signature-key-store.provider.ts. They are
// matched against the alias and tag the provider attaches at runtime, so a mismatch is not caught
// at build time — it surfaces as AccessDenied from KMS after deploy.
const VERIFIER_KEY_ALIAS_PREFIX = 'alias/vcknots/verifiers/';
const VERIFIER_KEY_TAG_KEY = 'vcknots:verifier-signature-key';

// Must match VERIFIER_CERTIFICATE_SECRET_PREFIX in aws/src/providers/secrets-manager.ts.
// Passed to the Lambda as an env var so the grant below and the provider cannot drift apart.
const VERIFIER_CERTIFICATE_SECRET_PREFIX = 'vcknots/verifier-certificates';

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
        VERIFIER_CERTIFICATE_SECRET_PREFIX,
      },
    });

    // The verifier creates and uses JAR signing keys at runtime (kmsVerifierSignatureKeyStore).
    grantSignatureKeyStoreAccess(this, this.lambdaApi.role, {
      aliasPrefix: VERIFIER_KEY_ALIAS_PREFIX,
      tagKey: VERIFIER_KEY_TAG_KEY,
    });

    // The verifier's X.509 chain is stored per verifier id under a name the provider derives
    // at runtime, so no secret can be provisioned here and referenced by ARN. Secrets Manager
    // appends a random six-character suffix to every secret ARN, hence the trailing wildcard.
    const stack = Stack.of(this);
    const verifierCertificateSecretArn = `arn:${stack.partition}:secretsmanager:${stack.region}:${stack.account}:secret:${VERIFIER_CERTIFICATE_SECRET_PREFIX}/*`;

    // CreateSecret has no resource-level permissions: the secret's ARN does not exist yet when
    // the request is made, so it must be scoped with Resource: '*' plus a secretsmanager:Name
    // condition instead — an ARN-scoped statement would deny every first-time registration.
    this.lambdaApi.role.addToPolicy(
      new iam.PolicyStatement({
        actions: ['secretsmanager:CreateSecret'],
        resources: ['*'],
        conditions: {
          StringLike: {
            'secretsmanager:Name': `${VERIFIER_CERTIFICATE_SECRET_PREFIX}/*`,
          },
        },
      }),
    );

    // PutSecretValue on re-registration, GetSecretValue on every JAR signed for an
    // x509_san_dns / x509_san_uri client id. Secrets encrypted with the aws/secretsmanager
    // managed key need no separate kms grant for a same-account role.
    this.lambdaApi.role.addToPolicy(
      new iam.PolicyStatement({
        actions: ['secretsmanager:PutSecretValue', 'secretsmanager:GetSecretValue'],
        resources: [verifierCertificateSecretArn],
      }),
    );
  }
}
