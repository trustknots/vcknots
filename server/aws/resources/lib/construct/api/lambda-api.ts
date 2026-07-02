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

/** GET/POST/DELETE cover server-core routes; OPTIONS is added for preflight. */
const corsAllowMethods = ['GET', 'POST', 'DELETE', 'OPTIONS'];

function corsAllowOrigins(): string[] {
  const configured = process.env.CORS_ALLOWED_ORIGINS?.split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  if (configured && configured.length > 0) {
    return configured;
  }
  // test/dev: permissive CORS for local wallets and conformance tools.
  if (apiStage !== 'prod') {
    return apigateway.Cors.ALL_ORIGINS;
  }
  throw new Error(
    'CORS_ALLOWED_ORIGINS must be set when API_STAGE=prod (comma-separated HTTPS origins)',
  );
}

function stageScopedLogGroupName(serviceName: string): string {
  return `/vcknots/${apiStage}/${serviceName}`;
}

function stageScopedRestApiName(serviceName: string): string {
  return `vcknots-${serviceName}-${apiStage}`;
}

export interface LambdaApiProps {
  /** Handler file name under server/aws/lambda/src/handlers/ (e.g. issuer.ts). */
  handlerFile: string;
  /** Short service id used in stage-scoped physical names (e.g. issuer → /vcknots/{stage}/issuer). */
  serviceName: string;
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
      logGroupName: stageScopedLogGroupName(props.serviceName),
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
      runtime: lambda.Runtime.NODEJS_24_X,
      architecture: lambda.Architecture.ARM_64,
      timeout: Duration.seconds(29),
      memorySize: 512,
      role: this.role,
      logGroup,
      bundling: {
        format: lambdaNode.OutputFormat.ESM,
        // CJS packages bundled into ESM output need a require() polyfill.
        // createRequire makes require available in the module scope so that
        // esbuild's __require2 helper can find it at runtime.
        banner: 'import { createRequire } from "module"; const require = createRequire(import.meta.url);',
      },
      environment: {
        NODE_ENV: 'production',
        API_STAGE: apiStage,
        ...props.environment,
      },
    });

    this.restApi = new apigateway.LambdaRestApi(this, 'RestApi', {
      handler: this.handler,
      proxy: true,
      restApiName: stageScopedRestApiName(props.serviceName),
      deployOptions: {
        stageName: apiStage,
        throttlingBurstLimit: 100,
        throttlingRateLimit: 50,
      },
      defaultCorsPreflightOptions: {
        allowOrigins: corsAllowOrigins(),
        allowMethods: corsAllowMethods,
        allowHeaders: apigateway.Cors.DEFAULT_HEADERS,
      },
    });

    this.handler.addEnvironment('API_GATEWAY_ID', this.restApi.restApiId);
  }
}
