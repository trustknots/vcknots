import { Construct } from 'constructs';
import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as lambdaNode from 'aws-cdk-lib/aws-lambda-nodejs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { Duration } from 'aws-cdk-lib';
import { handlerEntry } from '../../util/paths';

const apiStage = process.env.API_STAGE ?? 'test';

export interface LambdaApiProps {
  /** Handler file name under lib/handlers/ (e.g. issuer.ts). */
  handlerFile: string;
  restApiName: string;
  logGroupName: string;
  readWriteTables?: dynamodb.ITable[];
  writeOnlyTables?: dynamodb.ITable[];
  environment?: Record<string, string>;
}

/** Reusable Lambda + API Gateway (proxy) pair. */
export class LambdaApi extends Construct {
  public readonly role: iam.Role;
  public readonly handler: lambdaNode.NodejsFunction;
  public readonly restApi: apigateway.LambdaRestApi;

  constructor(scope: Construct, id: string, props: LambdaApiProps) {
    super(scope, id);

    const logGroup = new logs.LogGroup(this, 'LogGroup', {
      logGroupName: props.logGroupName,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    this.role = new iam.Role(this, 'LambdaRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    for (const table of props.readWriteTables ?? []) {
      table.grantReadWriteData(this.role);
    }
    for (const table of props.writeOnlyTables ?? []) {
      table.grantWriteData(this.role);
    }

    logGroup.grantWrite(this.role);

    this.handler = new lambdaNode.NodejsFunction(this, 'Handler', {
      entry: handlerEntry(props.handlerFile),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_LATEST,
      architecture: lambda.Architecture.ARM_64,
      timeout: Duration.seconds(29),
      memorySize: 512,
      role: this.role,
      logGroup,
      environment: {
        NODE_ENV: 'production',
        API_STAGE: apiStage,
        ...props.environment,
      },
    });

    this.restApi = new apigateway.LambdaRestApi(this, 'RestApi', {
      handler: this.handler,
      proxy: true,
      restApiName: props.restApiName,
      deployOptions: {
        stageName: apiStage,
        throttlingBurstLimit: 100,
        throttlingRateLimit: 50,
      },
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: apigateway.Cors.DEFAULT_HEADERS,
      },
    });

    this.handler.addEnvironment('API_GATEWAY_ID', this.restApi.restApiId);
  }
}
