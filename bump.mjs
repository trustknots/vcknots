#!/usr/bin/env node
import { execSync } from "child_process"
import fs from "fs"
import path from "path"

function now() {
  return new Date().toISOString()
}

console.log(`\n🚀 bump.mjs start  ${now()}`)

/* =========================
   Logger
========================= */

function createLogger(pkgName) {
  const safeName = pkgName.replace(/[\/@]/g, "_")
  const logFile = `bump-${safeName}.log`
  const stream = fs.createWriteStream(logFile, { flags: "w" })

  const LOG_LEVEL = process.env.LOG_LEVEL || "info" // info / debug

  function log(message = "", level = "info") {
    if (level === "debug" && LOG_LEVEL !== "debug") return
    console.log(message)
    stream.write(message + "\n")
  }

  return { log, close: () => stream.end() }
}

/* =========================
   Utils
========================= */

function run(cmd) {
  try {
    return execSync(cmd, { stdio: ["pipe", "pipe", "ignore"] })
      .toString()
      .trim()
  } catch {
    return ""
  }
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

/* =========================
   Package detection
========================= */

const ROOT_PACKAGES = [
  "issuer+verifier",
  "google-cloud",
  "docusaurus"
]

function getServerPackages() {
  if (!fs.existsSync("server")) return []

  return fs.readdirSync("server")
    .map(dir => path.join("server", dir))
    .filter(dir =>
      fs.existsSync(path.join(dir, "package.json"))
    )
}

function getAllPackagePaths() {
  return [
    ...ROOT_PACKAGES,
    ...getServerPackages()
  ].filter(p =>
    fs.existsSync(path.join(p, "package.json"))
  )
}

/* =========================
   Git
========================= */

function getLastTag(pkgName) {
  const baseName = pkgName.includes("/")
    ? pkgName.split("/").pop()
    : pkgName

  const safe = escapeRegex(baseName)
  const pattern = `${safe}@*`

  const tags = run(
    `git tag --list "${pattern}" --sort=-v:refname`
  )
    .split("\n")
    .filter(Boolean)

  return {
    tag: tags[0] || null,
    pattern
  }
}

function getCommitsSince(tag) {
  const range = tag ? `${tag}..HEAD` : ""
  const log = run(
    `git log ${range} --pretty=format:%H:::%s`
  )

  if (!log) return []

  return log.split("\n").map(line => {
    const [hash, subject] = line.split(":::")
    return { hash, subject }
  })
}

/* =========================
   Commit parsing
========================= */

function parseCommit(subject) {
  const match =
    subject.match(/^(\w+)(!)?(?:\(([^)]+)\))?(!)?:\s(.+)$/)

  if (!match) return null

  return {
    type: match[1],
    scope: match[3] ?? null,
    breaking: !!match[2] || !!match[4],
    subject
  }
}

function scopeMatches(pkgName, scope) {
  if (!scope) return false

  const s = scope.toLowerCase()

  const SCOPE_MAP = {
    "@trustknots/vcknots": [
      "@trustknots/vcknots",
      "vcknots",
      "issuer+verifier"
    ],
    "@trustknots/google-cloud": [
      "@trustknots/google-cloud",
      "google-cloud"
    ],
    "@trustknots/server": [
      "@trustknots/server",
      "server",
      "server/single",
      "single-server",
    ],
    "@trustknots/multi-server": [
      "@trustknots/multi-server",
      "server/multi",
      "multi-server",
    ],
    "@trustknots/server-core": [
      "@trustknots/server-core",
      "server/core",
      "core-server",
    ]
  }

  const allowed = SCOPE_MAP[pkgName]

  if (!allowed) return false

  return allowed.includes(s)
}

function analyzeForPackage(pkgName, commits) {
  let level = null

  const bumpRules = {
    major: [],
    minor: ['feat'],
    patch: ['fix', 'perf', 'refactor']
  }

  const matched = {
    major: [],
    minor: [],
    patch: []
  }

  const ignored = []

  for (const c of commits) {
    const parsed = parseCommit(c.subject)

    if (!parsed) {
      ignored.push({ ...c, reason: "invalid format" })
      continue
    }

    if (!scopeMatches(pkgName, parsed.scope)) {
      ignored.push({
        ...c,
        reason: `scope mismatch (${parsed.scope})`
      })
      continue
    }

    if (parsed.breaking) {
      matched.major.push(c)
      level = "major"
      continue
    }

    if (bumpRules.minor.includes(parsed.type)) {
      if (level !== "major") level = "minor"
      matched.minor.push(c)
      continue
    }

    if (bumpRules.patch.includes(parsed.type)) {
      if (!level) level = "patch"
      matched.patch.push(c)
      continue
    }

    ignored.push({
      ...c,
      reason: `unsupported type (${parsed.type})`
    })
  }

  if (!level) {
    return { level: null, matched, ignored }
  }

  return { level, matched, ignored }
}

/* =========================
   Main
========================= */

function main() {
  const packagePaths = getAllPackagePaths()
  const releases = {}

  for (const pkgPath of packagePaths) {
    const pkgJson = JSON.parse(
      fs.readFileSync(
        path.join(pkgPath, "package.json")
      )
    )

    const pkgName = pkgJson.name
    const { log, close } = createLogger(pkgName)

    log(`\n📦 package: ${pkgName}`)

    const { tag: lastTag, pattern } =
      getLastTag(pkgName)

    log(`   tag pattern: ${pattern}`)
    log(`   latest tag: ${lastTag ?? "none"}`)

    const commits =
      getCommitsSince(lastTag)

    log(`   commits since tag: ${commits.length}`)

    const { level, matched, ignored } =
      analyzeForPackage(pkgName, commits)

    log(`   bump decision: ${level ?? "none"}`)

    for (const type of ["major", "minor", "patch"]) {
      log(`   ${type}: ${matched[type].length}`)
      matched[type].forEach(c =>
        log(`     - ${c.hash.slice(0, 7)} ${c.subject}`)
      )
    }

    log(`   ignored: ${ignored.length}`)
    ignored.forEach(c =>
      log(
        `     - ${c.hash.slice(0, 7)} ${c.subject} [${c.reason}]`,
        "debug"
      )
    )

    close()

    if (level) {
      releases[pkgName] = level
    }
  }

  if (Object.keys(releases).length === 0) {
    console.log("\n⚠️  no releases detected")
    return
  }

  const timestamp = new Date()
    .toISOString()
    .replace(/[-:T]/g, "")
    .slice(0, 14)

  const fileName =
    `.changeset/changeset-${timestamp}.md`

  let content = "---\n"

  for (const [pkg, level] of Object.entries(
    releases
  )) {
    content += `"${pkg}": ${level}\n`
  }

  content += "---\n\n"
  content += `generated at ${timestamp}\n`

  fs.mkdirSync(".changeset", {
    recursive: true
  })

  fs.writeFileSync(fileName, content)

  console.log(`\n✅ generated: ${fileName}`)
}

main()

console.log(
  `🏁 bump.mjs end    ${now()}\n`
)