import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { AuthzApi } from './construct/api/authz-api';
import { IssuerApi } from './construct/api/issuer-api';
import { VerifierApi } from './construct/api/verifier-api';
import { DataStores } from './construct/data/data-stores';

export class ResourcesStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const dataStores = new DataStores(this, 'DataStores');

    const issuerApi = new IssuerApi(this, 'IssuerApi', dataStores);
    const authzApi = new AuthzApi(this, 'AuthzApi', dataStores);
    const verifierApi = new VerifierApi(this, 'VerifierApi', dataStores);

    new cdk.CfnOutput(this, 'IssuerApiUrl', {
      value: issuerApi.lambdaApi.restApi.url,
      description: 'Issuer API Gateway invoke URL',
    });
    new cdk.CfnOutput(this, 'AuthzApiUrl', {
      value: authzApi.lambdaApi.restApi.url,
      description: 'Authz API Gateway invoke URL',
    });
    new cdk.CfnOutput(this, 'VerifierApiUrl', {
      value: verifierApi.lambdaApi.restApi.url,
      description: 'Verifier API Gateway invoke URL',
    });
    new cdk.CfnOutput(this, 'IssuersTableName', {
      value: dataStores.issuersTable.tableName,
      description: 'Issuers DynamoDB table name',
    });
    new cdk.CfnOutput(this, 'AuthServersTableName', {
      value: dataStores.authServersTable.tableName,
      description: 'Auth servers DynamoDB table name',
    });
    new cdk.CfnOutput(this, 'PreCodesTableName', {
      value: dataStores.preCodesTable.tableName,
      description: 'Pre-authorized codes DynamoDB table name',
    });
    new cdk.CfnOutput(this, 'NoncesTableName', {
      value: dataStores.noncesTable.tableName,
      description: 'Nonces DynamoDB table name',
    });
    new cdk.CfnOutput(this, 'VerifiersTableName', {
      value: dataStores.verifiersTable.tableName,
      description: 'Verifiers DynamoDB table name',
    });
    new cdk.CfnOutput(this, 'RequestObjectsTableName', {
      value: dataStores.requestObjectsTable.tableName,
      description: 'Request objects DynamoDB table name',
    });
    new cdk.CfnOutput(this, 'AuthzOAuthPoliciesTableName', {
      value: dataStores.authzOAuthPoliciesTable.tableName,
      description: 'Authz OAuth policies DynamoDB table name',
    });
  }
}
