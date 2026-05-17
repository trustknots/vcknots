import 'dotenv/config'
import { createServer } from '@trustknots/server-core'
import { credentialProofJWT, dpopProof } from '@trustknots/vcknots/providers'

const DPOP_PROOF_MAX_TOKEN_AGE_SECONDS = 10 * 60
const DPOP_PROOF_CLOCK_TOLERANCE_SECONDS = 60

// Create a server in-memory Providers
// createServer()
createServer({
  providers: [
    credentialProofJWT({
      maxTokenAgeSeconds: 600,
      clockToleranceSeconds: 60,
    }),
    dpopProof({
      maxTokenAgeSeconds: DPOP_PROOF_MAX_TOKEN_AGE_SECONDS,
      clockToleranceSeconds: DPOP_PROOF_CLOCK_TOLERANCE_SECONDS,
    }),
  ],
})
