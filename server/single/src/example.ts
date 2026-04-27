import 'dotenv/config'
import { createServer } from '@trustknots/server-core'
import type { DPoPMode } from '@trustknots/vcknots'
import { credentialProofJWT, dpopProof } from '@trustknots/vcknots/providers'

const supportedDpopModes = ['off', 'optional', 'required'] as const
const DEFAULT_DPOP_PROOF_MAX_TOKEN_AGE_SECONDS = 24 * 60 * 60
const DEFAULT_DPOP_PROOF_CLOCK_TOLERANCE_SECONDS = 120

const isDpopMode = (value: string): value is DPoPMode =>
  supportedDpopModes.some((mode) => mode === value)

const rawDpopMode = process.env.DPOP_MODE ?? 'optional'

if (!isDpopMode(rawDpopMode)) {
  throw new Error('DPOP_MODE must be one of: off, optional, required')
}

// Create a server in-memory Providers
// createServer()
createServer({
  oauth: {
    // DPoP を使わない場合は次のように設定します:
    // senderConstrainedAccessToken: { method: 'none' },
    senderConstrainedAccessToken: {
      dpop: {
        mode: rawDpopMode,
      },
    },
  },
  providers: [
    credentialProofJWT({
      maxTokenAgeSeconds: 600,
      clockToleranceSeconds: 60,
    }),
    dpopProof({
      maxTokenAgeSeconds: DEFAULT_DPOP_PROOF_MAX_TOKEN_AGE_SECONDS,
      clockToleranceSeconds: DEFAULT_DPOP_PROOF_CLOCK_TOLERANCE_SECONDS,
    }),
  ],
})
