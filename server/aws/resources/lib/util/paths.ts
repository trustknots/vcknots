import * as path from 'path';

/** Absolute path to server/aws/resources (CDK is run from this directory). */
export function getResourcesRoot(): string {
  return process.cwd();
}

/** Absolute path to server/aws/lambda (@trustknots/server-aws). */
export function getLambdaRoot(): string {
  return path.join(getResourcesRoot(), '..', 'lambda');
}

export function handlerEntry(handlerFile: string): string {
  return path.join(getLambdaRoot(), 'handlers', handlerFile);
}
