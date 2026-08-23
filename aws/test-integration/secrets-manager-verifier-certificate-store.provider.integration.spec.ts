// Integration tests for secretsManagerVerifierCertificateStore against a real AWS account. These
// hit real Secrets Manager APIs (CreateSecret, PutSecretValue, GetSecretValue) and are NOT part of
// the default `test`/`test:ci` task — run explicitly via `pnpm test:integration` with credentials
// for the target account, e.g.:
//
//   cd aws && AWS_PROFILE=vc-knots AWS_REGION=ap-northeast-1 pnpm test:integration
//
// Every secret created here is force-deleted in the top-level `after` hook. Without
// ForceDeleteWithoutRecovery the name would stay reserved for the recovery window (7-30 days),
// and a re-run against the same verifier id would fail.
import assert from 'node:assert/strict'
import { X509Certificate, createHash } from 'node:crypto'
import { after, describe, it } from 'node:test'
import { DeleteSecretCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager'
import { Certificate } from '@trustknots/vcknots'
import { VerifierClientId } from '@trustknots/vcknots/verifier'
import { VERIFIER_CERTIFICATE_SECRET_PREFIX } from '../src/providers/secrets-manager'
import { secretsManagerVerifierCertificateStore } from '../src/providers/secrets-manager-verifier-certificate-store.provider'

// Throwaway self-signed certificate (CN=localhost, SAN=DNS:localhost, valid until 2036). The store
// never validates the chain, but real DER means fetch() output can be parsed back into an
// X509Certificate — which is what the wallet ultimately does with the x5c header.
const SAMPLE_CERTIFICATE_PEM = `-----BEGIN CERTIFICATE-----
MIIBkzCCATmgAwIBAgIUDRFFfGe1ZpbbEe0SeCXCRHcw97AwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgwNzA4NDQzN1oXDTM2MDgwNDA4
NDQzN1owFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE+W/uOVKWZhHStWoKG7iGdc3F2lJekfQZswpyDXijk5LzcvnWRz2wn92C
ceFWaRmGhbdZ9RWSpjp2/V73KKsGVKNpMGcwHQYDVR0OBBYEFJfJ7NXDMUKRF9NA
B0Yrn2I/h1OgMB8GA1UdIwQYMBaAFJfJ7NXDMUKRF9NAB0Yrn2I/h1OgMA8GA1Ud
EwEB/wQFMAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxob3N0MAoGCCqGSM49BAMCA0gA
MEUCIQD/nlqxJcsO6KYgtRGxTXoJXa1n96NKY4UYXpfAlpG+mQIgegiuC2bQnl2n
+S4bd5nY2odash+iUwokdOJiiACkmEQ=
-----END CERTIFICATE-----`

const RUN_ID = Date.now().toString(36)
const verifierFor = (label: string) =>
  VerifierClientId(`https://integration-test.example.com/${label}-${RUN_ID}`)

const secretsManager = new SecretsManagerClient({})
const store = secretsManagerVerifierCertificateStore()

const sha256Hex = (value: string) => createHash('sha256').update(value).digest('hex')

const createdSecretNames: string[] = []
const trackCreatedSecret = (verifier: string, prefix = VERIFIER_CERTIFICATE_SECRET_PREFIX) =>
  createdSecretNames.push(`${prefix}/${sha256Hex(verifier)}`)

const stripPem = (pem: string) =>
  pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '')
    .trim()

after(async () => {
  for (const name of createdSecretNames) {
    try {
      await secretsManager.send(
        new DeleteSecretCommand({ SecretId: name, ForceDeleteWithoutRecovery: true })
      )
    } catch {
      // Nothing to clean up if the secret was never created.
    }
  }
})

describe('secretsManagerVerifierCertificateStore round trip', () => {
  const verifier = verifierFor('round-trip')
  trackCreatedSecret(verifier)
  const certificate = Certificate([SAMPLE_CERTIFICATE_PEM])

  it('save() creates the secret without throwing', async () => {
    await assert.doesNotReject(store.save(verifier, certificate))
  })

  it('fetch() returns the chain as bare base64 DER', async () => {
    const fetched = await store.fetch(verifier)
    assert.deepEqual(fetched, [stripPem(SAMPLE_CERTIFICATE_PEM)])
  })

  it('fetched DER parses back into an X.509 certificate', async () => {
    const [der] = await store.fetch(verifier)
    const parsed = new X509Certificate(Buffer.from(der, 'base64'))
    assert.equal(parsed.subject, 'CN=localhost')
    assert.equal(parsed.subjectAltName, 'DNS:localhost')
  })

  it('save() again replaces the value instead of failing on the existing secret', async () => {
    await assert.doesNotReject(
      store.save(verifier, Certificate([SAMPLE_CERTIFICATE_PEM, SAMPLE_CERTIFICATE_PEM]))
    )
    assert.equal((await store.fetch(verifier)).length, 2)
  })
})

describe('secretsManagerVerifierCertificateStore on an unregistered verifier', () => {
  it('fetch() returns an empty certificate rather than throwing', async () => {
    assert.deepEqual(await store.fetch(verifierFor('never-registered')), [])
  })
})

describe('secretsManagerVerifierCertificateStore with a custom prefix', () => {
  const verifier = verifierFor('custom-prefix')
  const secretPrefix = `${VERIFIER_CERTIFICATE_SECRET_PREFIX}/integration`
  const scopedStore = secretsManagerVerifierCertificateStore({ secretPrefix })
  trackCreatedSecret(verifier, secretPrefix)

  it('stores and reads back under the custom prefix', async () => {
    await scopedStore.save(verifier, Certificate([SAMPLE_CERTIFICATE_PEM]))
    assert.deepEqual(await scopedStore.fetch(verifier), [stripPem(SAMPLE_CERTIFICATE_PEM)])
  })

  it('is invisible to the default-prefix store', async () => {
    assert.deepEqual(await store.fetch(verifier), [])
  })
})
