import 'dotenv/config'
import { createServer } from '@trustknots/server-core'
import { credentialProofJWT } from '@trustknots/vcknots/providers'
// Create a server in-memory Providers
// createServer()
createServer({
  providers: [
    credentialProofJWT({
      maxTokenAgeSeconds: 600,
      clockToleranceSeconds: 60,
    }),
  ],
})
