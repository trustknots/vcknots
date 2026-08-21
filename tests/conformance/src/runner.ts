import { readFile, mkdir } from 'node:fs/promises'
import { createWriteStream } from 'node:fs'
import { format } from 'node:util'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'

import { ConformanceClient } from './conformance.js'

interface RunnerConfig {
  conformanceServer: string
  conformanceToken: string
  scenario: string
}

const RUNNER_CONFIG_PATH = new URL('../config/runner.json', import.meta.url)

const SCENARIOS_DIR = new URL('../config/scenarios/', import.meta.url)

/*
 * Runner log
 *
 * 起動時にログファイルを上書きし、
 * プロセス終了まで追記する。
 */
const LOG_FILE = fileURLToPath(new URL('../logs/runner.log', import.meta.url))

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

  if (typeof value.conformanceServer !== 'string' || value.conformanceServer.length === 0) {
    throw new Error('runner.json: "conformanceServer" must be a non-empty string')
  }

  if (typeof value.conformanceToken !== 'string' || value.conformanceToken.length === 0) {
    throw new Error('runner.json: "conformanceToken" must be a non-empty string')
  }

  if (typeof value.scenario !== 'string' || value.scenario.length === 0) {
    throw new Error('runner.json: "scenario" must be a non-empty string')
  }
}

async function main() {
  const closeLogging = await setupLogging()

  try {
    /*
     * Runner設定をJSONファイルから読み込む。
     */
    const runnerConfig = JSON.parse(await readFile(RUNNER_CONFIG_PATH, 'utf8'))

    validateRunnerConfig(runnerConfig)

    /*
     * シナリオディレクトリを決定する。
     *
     * 例:
     * config/scenarios/issuer-sd-jwt-vc/
     */
    const scenarioDir = new URL(`${runnerConfig.scenario}/`, SCENARIOS_DIR)

    const metadataConfigPath = new URL('metadata.json', scenarioDir)

    const planConfigPath = new URL('plan.json', scenarioDir)

    const variantConfigPath = new URL('variant.json', scenarioDir)

    const planConfig = JSON.parse(await readFile(planConfigPath, 'utf8'))

    const variant = JSON.parse(await readFile(variantConfigPath, 'utf8'))

    const metadataConfig = JSON.parse(await readFile(metadataConfigPath, 'utf8'))

    const conformance = new ConformanceClient(
      runnerConfig.conformanceServer,
      runnerConfig.conformanceToken
    )

    console.log(`Scenario: ${runnerConfig.scenario}`)
    console.log(`Creating test plan: ${metadataConfig.testPlanName}`)

    /*
     * ① Test Planを作成
     */
    const plan = await conformance.createTestPlan(metadataConfig.testPlanName, planConfig, variant)

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
