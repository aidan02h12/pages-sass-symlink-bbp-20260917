'use strict'

const EXPECTED_REPOSITORY = 'aidan02h12/pages-sass-symlink-bbp-20260917'
const EXPECTED_REPOSITORY_ID = '1375300224'
const EXPECTED_OWNER_ID = '308023810'
const EXPECTED_RUN_NUMBER = '12'
const EXPECTED_RUN_ATTEMPT = '1'
const EXPECTED_REF = 'refs/heads/main'
const EXPECTED_AUDIENCE = 'https://github.com/aidan02h12'
const EXPECTED_ISSUER = 'https://token.actions.githubusercontent.com'
const EXPECTED_EVENT = 'dynamic'
const INVALID_BEARER = 'bbp-intentionally-invalid-oidc-control-r12-q4m7'
const MAX_RESPONSE_BYTES = 64 * 1024
const REQUEST_TIMEOUT_MS = 10_000
const MARKER_SUFFIX = '20260918_R12_Q4M7'

let requestCount = 0

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
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new Error('OIDC response too large')
  }
  if (!response.body) return Buffer.alloc(0)

  const chunks = []
  let total = 0
  for await (const chunk of response.body) {
    const buffer = Buffer.from(chunk)
    total += buffer.length
    if (total > MAX_RESPONSE_BYTES) {
      for (const prior of chunks) prior.fill(0)
      buffer.fill(0)
      throw new Error('OIDC response too large')
    }
    chunks.push(buffer)
  }
  const combined = Buffer.concat(chunks)
  for (const chunk of chunks) chunk.fill(0)
  return combined
}

async function requestOidc(url, bearer, fetchImpl = fetch) {
  requestCount += 1
  if (requestCount > 2) throw new Error('request budget exceeded')

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    const response = await fetchImpl(url, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${bearer}`,
        'user-agent': 'pages-bbp-owned-oidc-permission-boundary'
      },
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
    if (String(payload[name] ?? '') !== String(expected)) {
      throw new Error(`unexpected JWT claim: ${name}`)
    }
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
  if (payload.sub !== immutableSubject && payload.sub !== legacySubject) {
    throw new Error('unexpected JWT subject')
  }

  return {
    environmentClaimPresent: Object.prototype.hasOwnProperty.call(payload, 'environment'),
    immutableSubject: payload.sub === immutableSubject,
    workflowRefPresent: typeof payload.workflow_ref === 'string' && payload.workflow_ref.length > 0,
    jobWorkflowRefPresent: typeof payload.job_workflow_ref === 'string' && payload.job_workflow_ref.length > 0
  }
}

function validateLiveEnvironment(env) {
  if (env.PAGES_BBP_LIVE_OIDC_PROBE !== '1') throw new Error('live guard missing')
  if (env.GITHUB_REPOSITORY !== EXPECTED_REPOSITORY) throw new Error('repository guard mismatch')
  if (env.GITHUB_REPOSITORY_ID !== EXPECTED_REPOSITORY_ID) throw new Error('repository id guard mismatch')
  if (env.GITHUB_RUN_NUMBER !== EXPECTED_RUN_NUMBER) throw new Error('run number guard mismatch')
  if (env.GITHUB_RUN_ATTEMPT !== EXPECTED_RUN_ATTEMPT) throw new Error('run attempt guard mismatch')
  if (env.GITHUB_REF !== EXPECTED_REF) throw new Error('ref guard mismatch')
  if (!/^[0-9]+$/.test(env.GITHUB_RUN_ID || '')) throw new Error('run id guard mismatch')
  if (!/^[0-9a-f]{40}$/.test(env.GITHUB_SHA || '')) throw new Error('sha guard mismatch')
  if (!env.ACTIONS_ID_TOKEN_REQUEST_URL) throw new Error('OIDC request URL missing')
  if (!env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) throw new Error('OIDC request credential missing')
}

async function runProbe(env = process.env, fetchImpl = fetch) {
  validateLiveEnvironment(env)
  const oidcUrl = validateOidcUrl(env.ACTIONS_ID_TOKEN_REQUEST_URL)
  marker('PAGES_OIDC_URL_PRESENT')
  marker('PAGES_OIDC_REQUEST_CREDENTIAL_PRESENT')

  const invalid = await requestOidc(oidcUrl, INVALID_BEARER, fetchImpl)
  try {
    if (invalid.status !== 401 && invalid.status !== 403) {
      throw new Error('invalid OIDC control was not rejected')
    }
  } finally {
    invalid.body.fill(0)
  }
  marker('PAGES_OIDC_INVALID_CONTROL_REJECTED')

  const actual = await requestOidc(oidcUrl, env.ACTIONS_ID_TOKEN_REQUEST_TOKEN, fetchImpl)
  let parsed
  try {
    if (actual.status !== 200) throw new Error('actual OIDC request was not accepted')
    parsed = JSON.parse(actual.body.toString('utf8'))
  } catch (_) {
    throw new Error('actual OIDC response invalid')
  } finally {
    actual.body.fill(0)
  }
  marker('PAGES_OIDC_ACTUAL_REQUEST_ACCEPTED')

  const classification = validateJwt(parsed && parsed.value, env)
  marker('PAGES_OIDC_JWT_SHAPE_VALID')
  marker('PAGES_OIDC_CONTEXT_BOUND')
  marker(classification.environmentClaimPresent ? 'PAGES_OIDC_ENVIRONMENT_CLAIM_PRESENT' : 'PAGES_OIDC_ENVIRONMENT_CLAIM_ABSENT')
  marker(classification.immutableSubject ? 'PAGES_OIDC_IMMUTABLE_SUBJECT' : 'PAGES_OIDC_LEGACY_SUBJECT')
  marker(classification.workflowRefPresent ? 'PAGES_OIDC_WORKFLOW_REF_PRESENT' : 'PAGES_OIDC_WORKFLOW_REF_ABSENT')
  marker(classification.jobWorkflowRefPresent ? 'PAGES_OIDC_JOB_WORKFLOW_REF_PRESENT' : 'PAGES_OIDC_JOB_WORKFLOW_REF_ABSENT')

  if (requestCount !== 2) throw new Error('unexpected request count')
  marker('PAGES_OIDC_PERMISSION_BOUNDARY_PROBE_COMPLETED')
}

function fakeJwt(env) {
  const now = Math.floor(Date.now() / 1000)
  const encode = value => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
  const header = encode({alg: 'RS256', kid: 'offline-test-key', typ: 'JWT'})
  const payload = encode({
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
    iat: now,
    nbf: now - 5,
    exp: now + 300,
    jti: 'offline-only'
  })
  return `${header}.${payload}.offline_signature`
}

async function selfTest() {
  requestCount = 0
  const env = {
    PAGES_BBP_LIVE_OIDC_PROBE: '1',
    GITHUB_REPOSITORY: EXPECTED_REPOSITORY,
    GITHUB_REPOSITORY_ID: EXPECTED_REPOSITORY_ID,
    GITHUB_RUN_NUMBER: EXPECTED_RUN_NUMBER,
    GITHUB_RUN_ATTEMPT: EXPECTED_RUN_ATTEMPT,
    GITHUB_RUN_ID: '35370000000',
    GITHUB_SHA: '0123456789abcdef0123456789abcdef01234567',
    GITHUB_REF: EXPECTED_REF,
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://vstoken.actions.githubusercontent.com/owned?api-version=2.0',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'offline-real-request-credential'
  }
  const calls = []
  const fetchImpl = async (_url, options) => {
    calls.push(options.headers.authorization)
    if (calls.length === 1) return new Response('{"error":"invalid"}', {status: 401})
    return new Response(JSON.stringify({value: fakeJwt(env)}), {
      status: 200,
      headers: {'content-type': 'application/json'}
    })
  }
  await runProbe(env, fetchImpl)
  if (calls.length !== 2) throw new Error('self-test request count mismatch')
  if (calls[0] !== `Bearer ${INVALID_BEARER}`) throw new Error('self-test invalid control order mismatch')
  if (calls[1] !== `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`) throw new Error('self-test actual request order mismatch')
  process.stdout.write('OIDC_PROBE_SELF_TEST_OK\n')
}

async function main() {
  if (process.argv.includes('--self-test')) {
    await selfTest()
    return
  }
  await runProbe()
}

main().catch(() => {
  marker('PAGES_OIDC_PERMISSION_BOUNDARY_PROBE_FAILED', 'error')
  process.exitCode = 1
})
