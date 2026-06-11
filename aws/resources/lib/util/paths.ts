import * as path from 'path';

/** Absolute path to aws/resources (CDK is run from this directory). */
export function getResourcesRoot(): string {
  return process.cwd();
}

export function handlerEntry(handlerFile: string): string {
  return path.join(getResourcesRoot(), 'lib/handlers', handlerFile);
}
