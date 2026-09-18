'use strict'

const EXPECTED_REPOSITORY = 'aidan02h12/pages-sass-symlink-bbp-20260917'
const EXPECTED_REPOSITORY_ID = '1375300224'
const EXPECTED_OWNER_ID = '308023810'
const EXPECTED_RUN_NUMBER = '13'
const EXPECTED_RUN_ATTEMPT = '1'
const EXPECTED_REF = 'refs/heads/main'
const EXPECTED_AUDIENCE = 'https://github.com/aidan02h12'
const EXPECTED_ISSUER = 'https://token.actions.githubusercontent.com'
const EXPECTED_EVENT = 'dynamic'
const SAFE_ARTIFACT_ID = 10543164555
const PAGES_DEPLOYMENT_API = 'https://api.github.com/repos/aidan02h12/pages-sass-symlink-bbp-20260917/pages/deployments'
const EXPECTED_PAGE_URL = 'https://aidan02h12.github.io/pages-sass-symlink-bbp-20260917/'
const MAX_RESPONSE_BYTES = 64 * 1024
const REQUEST_TIMEOUT_MS = 10_000
const MARKER_SUFFIX = '20260918_R13_V6N2'

let requestCount = 0
let writeCount = 0

function marker(name, level = 'notice') {
  process.stderr.write(`::${level}::${name}_${MARKER_SUFFIX}\n`)
}

function validateOidcUrl(value) {
  const url = new URL(value)
  if (
    url.protocol !== 'https:' ||
    !url.hostname.endsWith('.actions.githubusercontent.com') ||
    url.username !== '' ||
    url.password !== '' ||
    url.port !== '' ||
    url.hash !== ''
  ) {
    throw new Error('unexpected OIDC service origin')
  }
  return url
}

async function readBounded(response) {
  const declared = Number(response.headers.get('content-length') || 0)
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) throw new Error('response too large')
  if (!response.body) return Buffer.alloc(0)

  const chunks = []
  let total = 0
  for await (const chunk of response.body) {
    const buffer = Buffer.from(chunk)
    total += buffer.length
    if (total > MAX_RESPONSE_BYTES) {
      for (const prior of chunks) prior.fill(0)
      buffer.fill(0)
      throw new Error('response too large')
    }
    chunks.push(buffer)
  }
  const combined = Buffer.concat(chunks)
  for (const chunk of chunks) chunk.fill(0)
  return combined
}

async function request(url, options, fetchImpl = fetch) {
  requestCount += 1
  if (requestCount > 2) throw new Error('request budget exceeded')
  if (options.method === 'POST') {
    writeCount += 1
    if (writeCount > 1) throw new Error('write budget exceeded')
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    const response = await fetchImpl(url, {
      ...options,
      redirect: 'error',
      signal: controller.signal
    })
    const body = await readBounded(response)
    return {status: response.status, body}
  } finally {
    clearTimeout(timer)
  }
}

function decodeJsonPart(value, label) {
  const buffer = Buffer.from(value, 'base64url')
  try {
    return JSON.parse(buffer.toString('utf8'))
  } catch (_) {
    throw new Error(`invalid JWT ${label}`)
  } finally {
    buffer.fill(0)
  }
}

function validateJwt(jwt, env) {
  if (typeof jwt !== 'string' || jwt.length < 100 || jwt.length > 16 * 1024) {
    throw new Error('invalid JWT length')
  }
  const parts = jwt.split('.')
  if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) {
    throw new Error('invalid JWT shape')
  }

  const header = decodeJsonPart(parts[0], 'header')
  const payload = decodeJsonPart(parts[1], 'payload')
  if (header.typ !== 'JWT' || header.alg !== 'RS256' || typeof header.kid !== 'string' || header.kid.length < 8) {
    throw new Error('unexpected JWT header')
  }

  const exactClaims = {
    iss: EXPECTED_ISSUER,
    aud: EXPECTED_AUDIENCE,
    repository: EXPECTED_REPOSITORY,
    repository_id: EXPECTED_REPOSITORY_ID,
    repository_owner_id: EXPECTED_OWNER_ID,
    repository_visibility: 'public',
    run_id: env.GITHUB_RUN_ID,
    run_number: EXPECTED_RUN_NUMBER,
    run_attempt: EXPECTED_RUN_ATTEMPT,
    ref: EXPECTED_REF,
    sha: env.GITHUB_SHA,
    event_name: EXPECTED_EVENT,
    runner_environment: 'github-hosted'
  }
  for (const [name, expected] of Object.entries(exactClaims)) {
    if (String(payload[name] ?? '') !== String(expected)) throw new Error(`unexpected JWT claim: ${name}`)
  }

  const now = Math.floor(Date.now() / 1000)
  const issuedAt = Number(payload.iat)
  const notBefore = Number(payload.nbf)
  const expiresAt = Number(payload.exp)
  if (
    !Number.isInteger(issuedAt) ||
    !Number.isInteger(notBefore) ||
    !Number.isInteger(expiresAt) ||
    issuedAt > now + 60 ||
    notBefore > now + 60 ||
    expiresAt <= now ||
    expiresAt - issuedAt < 60 ||
    expiresAt - issuedAt > 3600
  ) {
    throw new Error('unexpected JWT lifetime')
  }

  const immutableSubject =
    `repo:aidan02h12@${EXPECTED_OWNER_ID}/` +
    `pages-sass-symlink-bbp-20260917@${EXPECTED_REPOSITORY_ID}:ref:${EXPECTED_REF}`
  const legacySubject = `repo:${EXPECTED_REPOSITORY}:ref:${EXPECTED_REF}`
  if (payload.sub !== immutableSubject && payload.sub !== legacySubject) throw new Error('unexpected JWT subject')
  if (Object.prototype.hasOwnProperty.call(payload, 'environment')) {
    throw new Error('unexpected environment claim')
  }
  if (typeof payload.workflow_ref !== 'string' || payload.workflow_ref.length === 0) {
    throw new Error('workflow ref missing')
  }
  if (typeof payload.job_workflow_ref !== 'string' || payload.job_workflow_ref.length === 0) {
    throw new Error('job workflow ref missing')
  }
}

function validateLiveEnvironment(env) {
  if (env.PAGES_BBP_LIVE_DIRECT_DEPLOY_PROBE !== '1') throw new Error('live guard missing')
  if (env.GITHUB_REPOSITORY !== EXPECTED_REPOSITORY) throw new Error('repository guard mismatch')
  if (env.GITHUB_REPOSITORY_ID !== EXPECTED_REPOSITORY_ID) throw new Error('repository id guard mismatch')
  if (env.GITHUB_RUN_NUMBER !== EXPECTED_RUN_NUMBER) throw new Error('run number guard mismatch')
  if (env.GITHUB_RUN_ATTEMPT !== EXPECTED_RUN_ATTEMPT) throw new Error('run attempt guard mismatch')
  if (env.GITHUB_REF !== EXPECTED_REF) throw new Error('ref guard mismatch')
  if (!/^[0-9]+$/.test(env.GITHUB_RUN_ID || '')) throw new Error('run id guard mismatch')
  if (!/^[0-9a-f]{40}$/.test(env.GITHUB_SHA || '')) throw new Error('sha guard mismatch')
  if (!env.ACTIONS_ID_TOKEN_REQUEST_URL) throw new Error('OIDC request URL missing')
  if (!env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) throw new Error('OIDC request credential missing')
  if (!env.INPUT_TOKEN || !env.JEKYLL_GITHUB_TOKEN) throw new Error('Pages token missing')
  if (env.INPUT_TOKEN !== env.JEKYLL_GITHUB_TOKEN) throw new Error('Pages token binding mismatch')
}

function validateDeploymentResponse(value, env) {
  if (!value || typeof value !== 'object') throw new Error('deployment response missing')
  if (value.id != null && String(value.id) !== env.GITHUB_SHA) {
    throw new Error('deployment id mismatch')
  }

  const statusUrl = new URL(String(value.status_url || ''))
  const expectedStatusPath =
    `/repos/${EXPECTED_REPOSITORY}/pages/deployments/${env.GITHUB_SHA}`
  if (
    statusUrl.protocol !== 'https:' ||
    statusUrl.hostname !== 'api.github.com' ||
    statusUrl.port !== '' ||
    statusUrl.username !== '' ||
    statusUrl.password !== '' ||
    statusUrl.pathname !== expectedStatusPath ||
    statusUrl.search !== '' ||
    statusUrl.hash !== ''
  ) {
    throw new Error('deployment status URL mismatch')
  }

  const pageUrl = new URL(String(value.page_url || ''))
  const expectedPageUrl = new URL(EXPECTED_PAGE_URL)
  if (pageUrl.origin !== expectedPageUrl.origin || pageUrl.pathname !== expectedPageUrl.pathname) {
    throw new Error('deployment page URL mismatch')
  }
}

async function runProbe(env = process.env, fetchImpl = fetch) {
  validateLiveEnvironment(env)
  const oidcUrl = validateOidcUrl(env.ACTIONS_ID_TOKEN_REQUEST_URL)
  marker('PAGES_DIRECT_DEPLOY_PREREQUISITES_BOUND')

  const oidc = await request(
    oidcUrl,
    {
      method: 'GET',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`,
        'user-agent': 'pages-bbp-owned-direct-deploy-boundary'
      }
    },
    fetchImpl
  )
  let oidcBody
  try {
    if (oidc.status !== 200) throw new Error('OIDC request rejected')
    oidcBody = JSON.parse(oidc.body.toString('utf8'))
  } catch (_) {
    throw new Error('OIDC response invalid')
  } finally {
    oidc.body.fill(0)
  }
  validateJwt(oidcBody && oidcBody.value, env)
  marker('PAGES_DIRECT_DEPLOY_OIDC_MINT_ACCEPTED')
  marker('PAGES_DIRECT_DEPLOY_OIDC_ENVIRONMENT_CLAIM_ABSENT')

  const deployment = await request(
    PAGES_DEPLOYMENT_API,
    {
      method: 'POST',
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${env.INPUT_TOKEN}`,
        'content-type': 'application/json',
        'user-agent': 'pages-bbp-owned-direct-deploy-boundary',
        'x-github-api-version': '2026-03-10'
      },
      body: JSON.stringify({
        artifact_id: SAFE_ARTIFACT_ID,
        pages_build_version: env.GITHUB_SHA,
        oidc_token: oidcBody.value,
        environment: 'github-pages'
      })
    },
    fetchImpl
  )
  let deploymentBody
  try {
    if (deployment.status !== 200) throw new Error('Pages deployment request rejected')
    marker('PAGES_DIRECT_DEPLOY_POST_STATUS_200')
    deploymentBody = JSON.parse(deployment.body.toString('utf8'))
  } catch (_) {
    throw new Error('Pages deployment response invalid')
  } finally {
    deployment.body.fill(0)
  }
  validateDeploymentResponse(deploymentBody, env)
  marker('PAGES_DIRECT_DEPLOY_POST_ACCEPTED')
  marker('PAGES_DIRECT_DEPLOY_RESPONSE_BOUND')

  if (requestCount !== 2 || writeCount !== 1) throw new Error('unexpected request count')
  marker('PAGES_DIRECT_DEPLOY_BOUNDARY_PROBE_COMPLETED')
}

function fakeJwt(env, includeEnvironment = false) {
  const now = Math.floor(Date.now() / 1000)
  const encode = value => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
  const header = encode({alg: 'RS256', kid: 'offline-test-key', typ: 'JWT'})
  const payload = {
    iss: EXPECTED_ISSUER,
    aud: EXPECTED_AUDIENCE,
    sub:
      `repo:aidan02h12@${EXPECTED_OWNER_ID}/` +
      `pages-sass-symlink-bbp-20260917@${EXPECTED_REPOSITORY_ID}:ref:${EXPECTED_REF}`,
    repository: EXPECTED_REPOSITORY,
    repository_id: EXPECTED_REPOSITORY_ID,
    repository_owner_id: EXPECTED_OWNER_ID,
    repository_visibility: 'public',
    run_id: env.GITHUB_RUN_ID,
    run_number: EXPECTED_RUN_NUMBER,
    run_attempt: EXPECTED_RUN_ATTEMPT,
    ref: EXPECTED_REF,
    sha: env.GITHUB_SHA,
    event_name: EXPECTED_EVENT,
    runner_environment: 'github-hosted',
    workflow_ref: 'owned/offline/workflow@refs/heads/main',
    job_workflow_ref: 'owned/offline/job-workflow@refs/heads/main',
    iat: now,
    nbf: now - 5,
    exp: now + 300,
    jti: 'offline-only'
  }
  if (includeEnvironment) payload.environment = 'github-pages'
  return `${header}.${encode(payload)}.offline_signature`
}

async function selfTest() {
  requestCount = 0
  writeCount = 0
  const env = {
    PAGES_BBP_LIVE_DIRECT_DEPLOY_PROBE: '1',
    GITHUB_REPOSITORY: EXPECTED_REPOSITORY,
    GITHUB_REPOSITORY_ID: EXPECTED_REPOSITORY_ID,
    GITHUB_RUN_NUMBER: EXPECTED_RUN_NUMBER,
    GITHUB_RUN_ATTEMPT: EXPECTED_RUN_ATTEMPT,
    GITHUB_RUN_ID: '35380000000',
    GITHUB_SHA: '0123456789abcdef0123456789abcdef01234567',
    GITHUB_REF: EXPECTED_REF,
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://vstoken.actions.githubusercontent.com/owned?api-version=2.0',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'offline-oidc-request-credential',
    INPUT_TOKEN: 'offline-pages-token',
    JEKYLL_GITHUB_TOKEN: 'offline-pages-token'
  }
  const calls = []
  const jwt = fakeJwt(env)
  const fetchImpl = async (url, options) => {
    calls.push({url: String(url), method: options.method, authorization: options.headers.authorization})
    if (calls.length === 1) return new Response(JSON.stringify({value: jwt}), {status: 200})
    return new Response(
      JSON.stringify({
        status_url: `${PAGES_DEPLOYMENT_API}/${env.GITHUB_SHA}`,
        page_url: EXPECTED_PAGE_URL
      }),
      {status: 200}
    )
  }

  await runProbe(env, fetchImpl)
  if (calls.length !== 2) throw new Error('self-test request count mismatch')
  if (calls[0].method !== 'GET' || calls[1].method !== 'POST') throw new Error('self-test request order mismatch')
  if (calls[0].authorization !== `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`) {
    throw new Error('self-test OIDC credential mismatch')
  }
  if (calls[1].authorization !== `Bearer ${env.INPUT_TOKEN}`) throw new Error('self-test Pages credential mismatch')

  let environmentGuarded = false
  try {
    validateJwt(fakeJwt(env, true), env)
  } catch (_) {
    environmentGuarded = true
  }
  if (!environmentGuarded) throw new Error('self-test environment-claim guard failed')
  process.stdout.write('DIRECT_DEPLOY_PROBE_SELF_TEST_OK\n')
}

async function main() {
  if (process.argv.includes('--self-test')) {
    await selfTest()
    return
  }
  await runProbe()
}

main().catch(() => {
  marker('PAGES_DIRECT_DEPLOY_BOUNDARY_PROBE_FAILED', 'error')
  process.exitCode = 1
})
