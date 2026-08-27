// Shared by every test-integration spec: these hit a real AWS account, and an expired or missing
// session doesn't fail when credentials are resolved — the SDK happily hands back a stale access
// key — it only fails once AWS rejects the token on an actual API call. Without this check, that
// shows up as the same "security token is invalid" error repeated across every single test in
// every file. GetCallerIdentity needs no IAM permissions, so it is the cheapest call that proves
// the session is actually valid; run it once, up front, so a bad session fails fast with one
// clear message instead of the whole suite grinding through the same error test by test.
import { before } from 'node:test'
import { GetCallerIdentityCommand, STSClient } from '@aws-sdk/client-sts'

export const requireAwsSession = () => {
  before(async () => {
    try {
      await new STSClient({}).send(new GetCallerIdentityCommand({}))
    } catch (error) {
      const profile = process.env.AWS_PROFILE ?? '<profile>'
      throw new Error(
        `No valid AWS session for test:integration. Log in first, e.g. "aws sso login --profile ${profile}". (${error})`
      )
    }
  })
}
