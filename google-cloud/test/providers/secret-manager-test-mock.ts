import { SecretManagerServiceClient } from '@google-cloud/secret-manager'

type SecretRecord = {
  versions: unknown[]
}

export type SecretManagerTestMock = {
  secrets: Map<string, SecretRecord>
  client: SecretManagerServiceClient
  calls: {
    createSecret: Array<{ parent: string; secretId: string }>
    addSecretVersion: Array<{ parent: string; data: string }>
    accessSecretVersion: Array<{ name: string }>
  }
}

const googleError = (code: number): Error & { code: number } =>
  Object.assign(new Error(`Google API error ${code}`), { code })

export const createSecretManagerTestMock = (): SecretManagerTestMock => {
  const secrets = new Map<string, SecretRecord>()
  const calls = {
    createSecret: [] as Array<{ parent: string; secretId: string }>,
    addSecretVersion: [] as Array<{ parent: string; data: string }>,
    accessSecretVersion: [] as Array<{ name: string }>,
  }

  const client = {
    projectPath: (projectId: string) => `projects/${projectId}`,
    secretPath: (projectId: string, secretId: string) =>
      `projects/${projectId}/secrets/${secretId}`,
    async createSecret({
      parent,
      secretId,
    }: {
      parent: string
      secretId: string
      secret: { replication: { automatic: Record<string, never> } }
    }) {
      calls.createSecret.push({ parent, secretId })

      const secretName = `${parent}/secrets/${secretId}`
      if (secrets.has(secretName)) throw googleError(6)
      secrets.set(secretName, { versions: [] })
    },
    async addSecretVersion({
      parent,
      payload,
    }: {
      parent: string
      payload: { data?: Uint8Array | Buffer }
    }) {
      const record = secrets.get(parent)
      if (!record) throw googleError(5)

      const data = payload.data ? Buffer.from(payload.data) : Buffer.alloc(0)
      calls.addSecretVersion.push({ parent, data: data.toString('utf8') })
      record.versions.push(new Uint8Array(data))
    },
    async accessSecretVersion({ name }: { name: string }) {
      calls.accessSecretVersion.push({ name })

      const secretName = name.replace(/\/versions\/latest$/, '')
      const record = secrets.get(secretName)
      if (!record || record.versions.length === 0) throw googleError(5)

      return [{ payload: { data: record.versions.at(-1) } }]
    },
  } as unknown as SecretManagerServiceClient

  return { secrets, client, calls }
}
