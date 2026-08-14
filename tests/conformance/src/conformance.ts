export interface TestModule {
  testModule: string
  variant?: Record<string, unknown>
}

export interface TestPlan {
  id: string
  modules: TestModule[]
}

export interface ModuleInstance {
  id: string
}

export interface ModuleInfo {
  id: string
  status: string
  [key: string]: unknown
}

export class ConformanceClient {
  private readonly baseUrl: string
  private readonly headers: Record<string, string>

  constructor(baseUrl: string, token?: string) {
    this.baseUrl = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`

    this.headers = {
      'Content-Type': 'application/json',
    }

    if (token) {
      this.headers.Authorization = `Bearer ${token}`
    }
  }

  private url(path: string): string {
    return new URL(path, this.baseUrl).toString()
  }

  async createTestPlan(
    planName: string,
    configuration: unknown,
    variant?: Record<string, unknown>
  ): Promise<TestPlan> {
    const url = new URL(this.url('api/plan'))

    url.searchParams.set('planName', planName)

    if (variant) {
      url.searchParams.set('variant', JSON.stringify(variant))
    }

    const response = await fetch(url, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify(configuration),
    })

    await this.assertStatus(response, 201, 'createTestPlan')

    return response.json() as Promise<TestPlan>
  }

  async createTestFromPlan(
    planId: string,
    testName: string,
    variant?: Record<string, unknown>
  ): Promise<ModuleInstance> {
    const url = new URL(this.url('api/runner'))

    url.searchParams.set('test', testName)
    url.searchParams.set('plan', planId)

    if (variant) {
      url.searchParams.set('variant', JSON.stringify(variant))
    }

    const response = await fetch(url, {
      method: 'POST',
      headers: this.headers,
    })

    await this.assertStatus(response, 201, 'createTestFromPlan')

    return response.json() as Promise<ModuleInstance>
  }

  async startTest(moduleId: string): Promise<unknown> {
    const response = await fetch(this.url(`api/runner/${moduleId}`), {
      method: 'POST',
      headers: this.headers,
    })

    await this.assertStatus(response, 200, 'startTest')

    return response.json()
  }

  async getModuleInfo(moduleId: string): Promise<ModuleInfo> {
    const response = await fetch(this.url(`api/info/${moduleId}`), {
      method: 'GET',
      headers: this.headers,
    })

    await this.assertStatus(response, 200, 'getModuleInfo')

    return response.json() as Promise<ModuleInfo>
  }

  async getTestLog(moduleId: string): Promise<unknown> {
    const response = await fetch(this.url(`api/log/${moduleId}`), {
      method: 'GET',
      headers: this.headers,
    })

    await this.assertStatus(response, 200, 'getTestLog')

    return response.json()
  }

  async waitForFinished(moduleId: string, timeoutMs = 240_000): Promise<ModuleInfo> {
    const deadline = Date.now() + timeoutMs
    let lastLogAt = 0

    while (Date.now() < deadline) {
      const info = await this.getModuleInfo(moduleId)

      console.log(`[${moduleId}] status=${info.status}`)

      if (info.status === 'FINISHED') {
        return info
      }

      if (info.status === 'INTERRUPTED') {
        await this.logInterruptedTest(moduleId, info)

        throw new Error(`Conformance test ${moduleId} was interrupted`)
      }

      /*
       * WAITING中は10秒ごとにConformance Suiteの
       * テストログを取得する。
       */
      if (info.status === 'WAITING' && Date.now() - lastLogAt >= 10_000) {
        lastLogAt = Date.now()

        await this.logTestProgress(moduleId)
      }

      await this.sleep(1_000)
    }

    throw new Error(`Timed out waiting for ${moduleId}`)
  }

  private async logTestProgress(moduleId: string): Promise<void> {
    try {
      const log = await this.getTestLog(moduleId)

      console.log(`=== TEST LOG [${moduleId}] ===`)
      console.log(JSON.stringify(log, null, 2))
    } catch (error) {
      console.error(`[${moduleId}] Failed to fetch test log`, error)
    }
  }

  private async logInterruptedTest(moduleId: string, info: ModuleInfo): Promise<void> {
    console.error('=== MODULE INFO ===')
    console.error(JSON.stringify(info, null, 2))

    try {
      const log = await this.getTestLog(moduleId)

      console.error('=== TEST LOG ===')
      console.error(JSON.stringify(log, null, 2))
    } catch (error) {
      console.error(`[${moduleId}] Failed to fetch test log`, error)
    }
  }

  private async assertStatus(
    response: Response,
    expected: number,
    operation: string
  ): Promise<void> {
    if (response.status === expected) {
      return
    }

    const body = await response.text()

    throw new Error(`${operation} failed: HTTP ${response.status}\n${body}`)
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms))
  }
}
