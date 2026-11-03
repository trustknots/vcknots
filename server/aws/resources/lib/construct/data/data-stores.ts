import { Construct } from 'constructs';
import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

const baseTableProps = {
  partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
  billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
  removalPolicy: cdk.RemovalPolicy.RETAIN,
  // Enable continuous backups so accidental writes/deletes can be restored.
  pointInTimeRecovery: true,
} as const;

export class DataStores extends Construct {
  public readonly issuersTable: dynamodb.Table;
  public readonly authServersTable: dynamodb.Table;
  public readonly preCodesTable: dynamodb.Table;
  public readonly noncesTable: dynamodb.Table;
  public readonly verifiersTable: dynamodb.Table;
  public readonly requestObjectsTable: dynamodb.Table;
  public readonly authzOAuthClientsTable: dynamodb.Table;
  public readonly authzOAuthPoliciesTable: dynamodb.Table;
  public readonly allowedCredentialConfigurationsTable: dynamodb.Table;
  public readonly dpopProofJtisTable: dynamodb.Table;
  public readonly oauthClientAssertionJtisTable: dynamodb.Table;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    // One table per data type. Each item is looked up by `id` (partition key).
    this.issuersTable = new dynamodb.Table(this, 'IssuersTable', baseTableProps);

    this.authServersTable = new dynamodb.Table(this, 'AuthServersTable', baseTableProps);

    this.preCodesTable = new dynamodb.Table(this, 'PreCodesTable', {
      ...baseTableProps,
      // `expires_at` is app-level epoch ms; DynamoDB TTL uses the epoch-seconds `ttl` attribute.
      timeToLiveAttribute: 'ttl',
    });

    this.noncesTable = new dynamodb.Table(this, 'NoncesTable', {
      ...baseTableProps,
      // `expires_at` is app-level epoch ms; DynamoDB TTL uses the epoch-seconds `ttl` attribute.
      timeToLiveAttribute: 'ttl',
    });

    this.verifiersTable = new dynamodb.Table(this, 'VerifiersTable', baseTableProps);

    this.requestObjectsTable = new dynamodb.Table(this, 'RequestObjectsTable', {
      ...baseTableProps,
      // `expires_at` is app-level epoch ms; DynamoDB TTL uses the epoch-seconds `ttl` attribute.
      timeToLiveAttribute: 'ttl',
    });

    // OAuth client registrations are persistent config, not ephemeral state — no TTL.
    this.authzOAuthClientsTable = new dynamodb.Table(this, 'AuthzOAuthClientsTable', baseTableProps);

    // OAuth policy is persistent config, not ephemeral state — no TTL.
    this.authzOAuthPoliciesTable = new dynamodb.Table(this, 'AuthzOAuthPoliciesTable', baseTableProps);

    // Credential configuration ids allowed per access token (keyed by access token hash).
    this.allowedCredentialConfigurationsTable = new dynamodb.Table(
      this,
      'AllowedCredentialConfigurationsTable',
      {
        ...baseTableProps,
        // `expires_at` is app-level epoch ms; DynamoDB TTL uses the epoch-seconds `ttl` attribute.
        timeToLiveAttribute: 'ttl',
      },
    );

    // Used DPoP proof jti values per proof key (keyed by sha256 of `jwkThumbprint:jti`).
    this.dpopProofJtisTable = new dynamodb.Table(this, 'DpopProofJtisTable', {
      ...baseTableProps,
      // `expires_at` is app-level epoch ms; DynamoDB TTL uses the epoch-seconds `ttl` attribute.
      timeToLiveAttribute: 'ttl',
    });

    // Used OAuth client assertion jti values per client (keyed by sha256 of `[clientId, jti]`).
    this.oauthClientAssertionJtisTable = new dynamodb.Table(this, 'OAuthClientAssertionJtisTable', {
      ...baseTableProps,
      // `expires_at` is app-level epoch ms; DynamoDB TTL uses the epoch-seconds `ttl` attribute.
      timeToLiveAttribute: 'ttl',
    });
  }
}
