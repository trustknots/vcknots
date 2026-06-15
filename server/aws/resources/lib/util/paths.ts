import * as path from 'path';

/** Absolute path to server/aws/resources (CDK is run from this directory). */
export function getResourcesRoot(): string {
  return process.cwd();
}

/** Absolute path to server/aws (Lambda handler sources). */
export function getServerAwsRoot(): string {
  return path.join(getResourcesRoot(), '..');
}

export function handlerEntry(handlerFile: string): string {
  return path.join(getServerAwsRoot(), 'handlers', handlerFile);
}
