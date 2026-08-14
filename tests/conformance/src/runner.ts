import { readFile, mkdir } from 'node:fs/promises'
import { createWriteStream } from 'node:fs'
import { format } from 'node:util'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'

import { ConformanceClient } from './conformance.js'

interface RunnerConfig {
  conformanceServer: string
  conformanceToken: string
}

const RUNNER_CONFIG_PATH = new URL('../config/runner.json', import.meta.url)

const TEST_PLAN_CONFIG_PATH = new URL(
  '../config/issuer-private-key-jwt.json',
  import.meta.url
)


/*
 * OpenID4VCI Issuer用のTest Plan
 */
const TEST_PLAN_NAME = 'oid4vci-1_0-issuer-test-plan'

/*
 * Test Planのvariant
 *
 * 実際のv5.2.2のIssuer Test Planに
 * 合わせて設定する。
 */
const TEST_VARIANT = {
  fapi_profile: 'vci',
  sender_constrain: 'dpop',
  client_auth_type: 'private_key_jwt',
  vci_authorization_code_flow_variant: 'issuer_initiated',
  credential_format: 'sd_jwt_vc',
  authorization_request_type: 'simple',
  fapi_request_method: 'unsigned',
  vci_grant_type: 'pre_authorization_code',
  vci_credential_encryption: 'plain',
}

/*
 * Runner log
 *
 * 起動時にログファイルを上書きし、
 * プロセス終了まで追記する。
 */
const LOG_FILE = fileURLToPath(
  new URL('../logs/runner.log', import.meta.url)
)

async function setupLogging() {
  await mkdir(dirname(LOG_FILE), { recursive: true })

  const logStream = createWriteStream(LOG_FILE, {
    flags: 'w',
  })

  const originalLog = console.log
  const originalError = console.error

  console.log = (...args: unknown[]) => {
    const message = format(...args)

    originalLog(...args)
    logStream.write(`${message}\n`)
  }

  console.error = (...args: unknown[]) => {
    const message = format(...args)

    originalError(...args)
    logStream.write(`${message}\n`)
  }

  return () => {
    logStream.end()
  }
}

function validateRunnerConfig(config: unknown): asserts config is RunnerConfig {
  if (typeof config !== 'object' || config === null) {
    throw new Error('runner.json must contain a JSON object')
  }

  const value = config as Record<string, unknown>

  if (
    typeof value.conformanceServer !== 'string' ||
    value.conformanceServer.length === 0
  ) {
    throw new Error(
      'runner.json: "conformanceServer" must be a non-empty string'
    )
  }

  if (
    typeof value.conformanceToken !== 'string' ||
    value.conformanceToken.length === 0
  ) {
    throw new Error(
      'runner.json: "conformanceToken" must be a non-empty string'
    )
  }
}

async function main() {
  const closeLogging = await setupLogging()

  try {
    /*
     * Runner設定をJSONファイルから読み込む。
     */
    const runnerConfig = JSON.parse(
      await readFile(RUNNER_CONFIG_PATH, 'utf8')
    )

    validateRunnerConfig(runnerConfig)

    /*
     * Test Plan ConfigurationをJSONファイルから読み込む。
     */
    const testPlanConfig = JSON.parse(
      await readFile(TEST_PLAN_CONFIG_PATH, 'utf8')
    )

    const conformance = new ConformanceClient(
      runnerConfig.conformanceServer,
      runnerConfig.conformanceToken
    )

    console.log(`Creating test plan: ${TEST_PLAN_NAME}`)

    /*
     * ① Test Planを作成
     */
    const plan = await conformance.createTestPlan(
      TEST_PLAN_NAME,
      testPlanConfig,
      TEST_VARIANT
    )

    console.log(`Test Plan created: ${plan.id}`)

    /*
     * ② Test Planに含まれる
     *    Test Moduleを順番に実行
     */
    for (const module of plan.modules) {
      console.log('')
      console.log(`Running: ${module.testModule}`)

      /*
       * Test Moduleのinstanceを作成
       */
      const instance = await conformance.createTestFromPlan(
        plan.id,
        module.testModule,
        module.variant
      )

      console.log(`Test instance: ${instance.id}`)

      /*
       * ③ Test開始
       */
      await conformance.startTest(instance.id)

      /*
       * ④ FINISHEDまで待つ
       *
       * WAITING中はConformance Suiteのテストログを
       * 10秒ごとに取得する。
       */
      const result = await conformance.waitForFinished(instance.id)

      console.log(`Finished: ${result.status}`)

      /*
       * FINISHED後の最終ログ
       */
      const log = await conformance.getTestLog(instance.id)

      console.log('=== FINAL TEST LOG ===')
      console.log(JSON.stringify(log, null, 2))
    }

    console.log('')
    console.log(`Conformance test plan completed: ${plan.id}`)
  } finally {
    closeLogging()
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})