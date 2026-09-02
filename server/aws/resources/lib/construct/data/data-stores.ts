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
  }
}
