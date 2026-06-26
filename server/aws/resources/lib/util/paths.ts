import * as path from 'path';

/**
 * Absolute path to the server/aws/resources package root.
 *
 * Derived from this file's location (lib/util → up two levels), not process.cwd(),
 * so CDK synth works even when invoked from another working directory.
 */
export function getResourcesRoot(): string {
  return path.resolve(__dirname, '..', '..');
}

/** Absolute path to server/aws/src (@trustknots/server-aws). */
export function getLambdaRoot(): string {
  return path.join(getResourcesRoot(), '..', 'src');
}

export function handlerEntry(handlerFile: string): string {
  return path.join(getLambdaRoot(), 'handlers', handlerFile);
}
