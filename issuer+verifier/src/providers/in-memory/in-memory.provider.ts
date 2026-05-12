import { inMemoryAuthzServerMetadata } from './in-memory-authz-metadata-store.provider'
import { inMemoryAuthzSignatureKeyStore } from './in-memory-authz-signature-key-store.provider'
import { inMemoryDpopProofJtiStore } from './in-memory-dpop-proof-jti-store.provider'
import { inMemoryNonceStore } from './in-memory-nonce-store.provider'
import { inMemoryIssuerMetadataStore } from './in-memory-issuer-metadata-store.provider'
import { inMemoryIssuerSignatureKeyStore } from './in-memory-issuer-signature-key-store.provider'
import { inMemoryPreAuthorizedCodeStore } from './in-memory-pre-authorized-code-store.provider'
import { inMemoryRequestObjectStore } from './in-memory-request-object-store.provider'
import { inMemoryVerifierCertificateStore } from './in-memory-verifier-certificate-store.provider'
import { inMemoryVerifierMetadataStore } from './in-memory-verifier-metadata-store.provider'
import { inMemoryVerifierSignatureKeyStore } from './in-memory-verifier-signature-key-store.provider'

export const inMemory = () => {
  return [
    inMemoryIssuerMetadataStore(),
    inMemoryPreAuthorizedCodeStore(),
    inMemoryVerifierMetadataStore(),
    inMemoryIssuerSignatureKeyStore(),
    inMemoryAuthzServerMetadata(),
    inMemoryAuthzSignatureKeyStore(),
    inMemoryDpopProofJtiStore(),
    inMemoryNonceStore(),
    inMemoryRequestObjectStore(),
    inMemoryVerifierSignatureKeyStore(),
    inMemoryVerifierCertificateStore(),
  ]
}
