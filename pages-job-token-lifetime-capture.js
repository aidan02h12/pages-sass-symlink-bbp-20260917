'use strict'

const crypto = require('crypto')

const ARTIFACT_NAME = 'bbp-pages-token-lifetime-r11-t9k3'
const ARCHIVE_ENTRY_NAME = 'run11-token-envelope.json'
const ENVELOPE_VERSION = 1
const ENVELOPE_AAD = Buffer.from('github-actions-job-token-lifetime-v1', 'utf8')
const PUBLIC_KEY_SPKI_SHA256 = '395d01ab58e0f28547666cc790efe01c966345de32a3923082d77d54a6f9e9ae'
const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA7K380wVvYGxgU0ngwx5SVy/jtuNhIhg3
ePEapbqvTOyxig77Puco7mYjqsrD5t6ZYf57fvk/dtgMk0Xwg1PhQyap1/gtyymifJyQ2RGWSzQt
XdbrbcwalbZILBvWQwlZ6ZSun4F7TK6/a2O6g3RFNzYepxk4mkjehMWt3MXdzDFZy6V+oXC2Bgum
pqTTK12A/Bu2P/wMeQiPTqKoEaPH90p03kThN45IbqwmaAvupCvETbb+W6356TF7Zkrkt8NTMpxD
b/n8Lyq2g0KntWwKAIzs8Fk0h8JbKwrnDrk9htPsoWvcboWF8E75mhptOUztTftP3ySyCzOqlauv
WQfiDlRaNBhfT2STTMHSKccYCmGaH6ZCnyeeX+nVVQ9NLt+II2wScd8OfJRVNp1iJqPlawQklR6B
PDqcYI1R8D9WJZkPcldHtyYjrVPem9lyJQ+15Y+C5FFLYx/R9nxjm6KMfCQMlfLb+7d4REpPzl4r
bWbHSkB7g3Wrc0B/HRjTCwexAgMBAAE=
-----END PUBLIC KEY-----
`
const MAX_RESPONSE_BYTES = 64 * 1024
const MAX_ARCHIVE_BYTES = 64 * 1024
const SERVICE = 'github.actions.results.api.v1.ArtifactService'
const EXPECTED_REPOSITORY = 'aidan02h12/pages-sass-symlink-bbp-20260917'
const EXPECTED_REPOSITORY_ID = '1375300224'
const OWNED_REPOSITORY_API = 'https://api.github.com/repos/aidan02h12/pages-sass-symlink-bbp-20260917'

function marker(name, level = 'notice') {
  process.stderr.write(`::${level}::${name}_20260918_R11_T9K3\n`)
}

function field(object, snakeName, camelName) {
  return object && (object[snakeName] ?? object[camelName])
}

function decodeBackendIds(token) {
  const parts = token.split('.')
  if (parts.length < 2) throw new Error('invalid runtime credential shape')

  const decoded = Buffer.from(parts[1], 'base64url')
  let payload
  try {
    payload = JSON.parse(decoded.toString('utf8'))
  } finally {
    decoded.fill(0)
  }
  const scopes = Array.isArray(payload.scp) ? payload.scp : String(payload.scp || '').split(' ')
  for (const scope of scopes) {
    const partsForScope = String(scope).split(':')
    if (partsForScope[0] !== 'Actions.Results' || partsForScope.length !== 3) continue
    const workflowRunBackendId = partsForScope[1]
    const workflowJobRunBackendId = partsForScope[2]
    if (
      !/^[A-Za-z0-9_-]{1,128}$/.test(workflowRunBackendId) ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(workflowJobRunBackendId)
    ) {
      throw new Error('invalid results scope')
    }
    return {workflowRunBackendId, workflowJobRunBackendId}
  }
  throw new Error('missing results scope')
}

function validateResultsOrigin(value) {
  const url = new URL(value)
  if (
    url.protocol !== 'https:' ||
    !url.hostname.endsWith('.actions.githubusercontent.com') ||
    url.username !== '' ||
    url.password !== '' ||
    url.port !== ''
  ) {
    throw new Error('unexpected results service host')
  }
  return url.origin
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
    throw new Error('unexpected artifact host')
  }
  return url
}

async function readBounded(response) {
  const declared = Number(response.headers.get('content-length') || 0)
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new Error('response too large')
  }
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
    } finally {
      raw.fill(0)
    }
    return {status: response.status, body: parsed}
  } finally {
    clearTimeout(timer)
  }
}

async function putArchive(url, archive) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 10000)
  try {
    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        'content-type': 'application/zip',
        'x-ms-blob-type': 'BlockBlob',
        'x-ms-version': '2021-08-06'
      },
      body: archive,
      redirect: 'error',
      signal: controller.signal
    })
    const raw = await readBounded(response)
    raw.fill(0)
    return {status: response.status}
  } finally {
    clearTimeout(timer)
  }
}

async function headOwnedRepository(token, fetchImpl = fetch) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 10000)
  try {
    const response = await fetchImpl(OWNED_REPOSITORY_API, {
      method: 'HEAD',
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'user-agent': 'pages-bbp-owned-token-lifetime-control'
      },
      redirect: 'error',
      signal: controller.signal
    })
    const raw = await readBounded(response)
    raw.fill(0)
    return response.status
  } finally {
    clearTimeout(timer)
  }
}

function encryptCredential(plaintext, publicKeyPem = PUBLIC_KEY_PEM) {
  const aesKey = crypto.randomBytes(32)
  const iv = crypto.randomBytes(12)
  let ciphertext = Buffer.alloc(0)
  let tag = Buffer.alloc(0)
  let wrappedKey = Buffer.alloc(0)
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv)
    cipher.setAAD(ENVELOPE_AAD)
    ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    tag = cipher.getAuthTag()
    wrappedKey = crypto.publicEncrypt(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      aesKey
    )

    return {
      version: ENVELOPE_VERSION,
      key_wrap: 'RSA-OAEP-SHA256',
      content_encryption: 'AES-256-GCM',
      public_key_spki_sha256: PUBLIC_KEY_SPKI_SHA256,
      aad_b64: ENVELOPE_AAD.toString('base64'),
      wrapped_key_b64: wrappedKey.toString('base64'),
      iv_b64: iv.toString('base64'),
      tag_b64: tag.toString('base64'),
      ciphertext_b64: ciphertext.toString('base64')
    }
  } finally {
    aesKey.fill(0)
    iv.fill(0)
    ciphertext.fill(0)
    tag.fill(0)
    wrappedKey.fill(0)
  }
}

function crc32(buffer) {
  let crc = 0xffffffff
  for (const byte of buffer) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0)
    }
  }
  return (crc ^ 0xffffffff) >>> 0
}

function buildSingleFileZip(name, contents) {
  const fileName = Buffer.from(name, 'utf8')
  if (fileName.length === 0 || fileName.length > 255 || contents.length > MAX_ARCHIVE_BYTES / 2) {
    throw new Error('invalid zip input')
  }
  const checksum = crc32(contents)
  const localHeader = Buffer.alloc(30)
  localHeader.writeUInt32LE(0x04034b50, 0)
  localHeader.writeUInt16LE(20, 4)
  localHeader.writeUInt16LE(0, 6)
  localHeader.writeUInt16LE(0, 8)
  localHeader.writeUInt16LE(0, 10)
  localHeader.writeUInt16LE(0x21, 12)
  localHeader.writeUInt32LE(checksum, 14)
  localHeader.writeUInt32LE(contents.length, 18)
  localHeader.writeUInt32LE(contents.length, 22)
  localHeader.writeUInt16LE(fileName.length, 26)
  localHeader.writeUInt16LE(0, 28)

  const centralHeader = Buffer.alloc(46)
  centralHeader.writeUInt32LE(0x02014b50, 0)
  centralHeader.writeUInt16LE(20, 4)
  centralHeader.writeUInt16LE(20, 6)
  centralHeader.writeUInt16LE(0, 8)
  centralHeader.writeUInt16LE(0, 10)
  centralHeader.writeUInt16LE(0, 12)
  centralHeader.writeUInt16LE(0x21, 14)
  centralHeader.writeUInt32LE(checksum, 16)
  centralHeader.writeUInt32LE(contents.length, 20)
  centralHeader.writeUInt32LE(contents.length, 24)
  centralHeader.writeUInt16LE(fileName.length, 28)
  centralHeader.writeUInt16LE(0, 30)
  centralHeader.writeUInt16LE(0, 32)
  centralHeader.writeUInt16LE(0, 34)
  centralHeader.writeUInt16LE(0, 36)
  centralHeader.writeUInt32LE(0, 38)
  centralHeader.writeUInt32LE(0, 42)

  const centralOffset = localHeader.length + fileName.length + contents.length
  const centralSize = centralHeader.length + fileName.length
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(0, 4)
  end.writeUInt16LE(0, 6)
  end.writeUInt16LE(1, 8)
  end.writeUInt16LE(1, 10)
  end.writeUInt32LE(centralSize, 12)
  end.writeUInt32LE(centralOffset, 16)
  end.writeUInt16LE(0, 20)

  const archive = Buffer.concat([localHeader, fileName, contents, centralHeader, fileName, end])
  if (archive.length === 0 || archive.length > MAX_ARCHIVE_BYTES) {
    archive.fill(0)
    throw new Error('invalid archive size')
  }
  return archive
}

function parseSingleFileZip(archive) {
  if (archive.length < 98 || archive.length > MAX_ARCHIVE_BYTES) throw new Error('invalid zip size')
  if (archive.readUInt32LE(0) !== 0x04034b50) throw new Error('missing local header')
  const nameLength = archive.readUInt16LE(26)
  const extraLength = archive.readUInt16LE(28)
  const compressedLength = archive.readUInt32LE(18)
  const uncompressedLength = archive.readUInt32LE(22)
  if (archive.readUInt16LE(8) !== 0 || compressedLength !== uncompressedLength) {
    throw new Error('unsupported zip method')
  }
  const dataStart = 30 + nameLength + extraLength
  const dataEnd = dataStart + uncompressedLength
  if (dataEnd + 68 > archive.length) throw new Error('truncated zip')

  const endOffset = archive.length - 22
  if (archive.readUInt32LE(endOffset) !== 0x06054b50) throw new Error('missing end record')
  if (archive.readUInt16LE(endOffset + 8) !== 1 || archive.readUInt16LE(endOffset + 10) !== 1) {
    throw new Error('unexpected entry count')
  }
  const centralSize = archive.readUInt32LE(endOffset + 12)
  const centralOffset = archive.readUInt32LE(endOffset + 16)
  if (centralOffset !== dataEnd || centralOffset + centralSize !== endOffset) {
    throw new Error('invalid central directory bounds')
  }
  if (archive.readUInt32LE(centralOffset) !== 0x02014b50) {
    throw new Error('missing central header')
  }

  const name = archive.subarray(30, 30 + nameLength).toString('utf8')
  const centralNameLength = archive.readUInt16LE(centralOffset + 28)
  const centralName = archive
    .subarray(centralOffset + 46, centralOffset + 46 + centralNameLength)
    .toString('utf8')
  const contents = Buffer.from(archive.subarray(dataStart, dataEnd))
  if (
    name !== centralName ||
    archive.readUInt32LE(14) !== crc32(contents) ||
    archive.readUInt32LE(centralOffset + 16) !== crc32(contents)
  ) {
    contents.fill(0)
    throw new Error('zip integrity failure')
  }
  return {name, contents}
}

function positiveId(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return String(value)
  return typeof value === 'string' && /^[1-9][0-9]*$/.test(value) ? value : ''
}

async function uploadEncryptedEnvelope(origin, runtimeToken, ids, archive, transport, emit) {
  const created = await transport.postJson(origin, 'CreateArtifact', runtimeToken, {
    workflow_run_backend_id: ids.workflowRunBackendId,
    workflow_job_run_backend_id: ids.workflowJobRunBackendId,
    name: ARTIFACT_NAME,
    version: 4
  })
  const signedUrl = field(created.body, 'signed_upload_url', 'signedUploadUrl')
  if (
    created.status !== 200 ||
    created.body?.ok !== true ||
    typeof signedUrl !== 'string' ||
    signedUrl.length === 0
  ) {
    emit('PAGES_JOB_TOKEN_ARTIFACT_RESERVATION_REJECTED')
    return false
  }
  emit('PAGES_JOB_TOKEN_ARTIFACT_RESERVATION_ACCEPTED', 'warning')

  let uploadUrl
  try {
    uploadUrl = validateBlobUrl(signedUrl)
  } catch (_) {
    emit('PAGES_JOB_TOKEN_ARTIFACT_SIGNED_URL_REJECTED')
    return false
  }

  const uploaded = await transport.putArchive(uploadUrl, archive)
  if (uploaded.status !== 200 && uploaded.status !== 201) {
    emit('PAGES_JOB_TOKEN_ARTIFACT_UPLOAD_REJECTED')
    return false
  }
  emit('PAGES_JOB_TOKEN_ARTIFACT_UPLOAD_ACCEPTED', 'warning')

  const finalized = await transport.postJson(origin, 'FinalizeArtifact', runtimeToken, {
    workflow_run_backend_id: ids.workflowRunBackendId,
    workflow_job_run_backend_id: ids.workflowJobRunBackendId,
    name: ARTIFACT_NAME,
    size: String(archive.length)
  })
  const artifactId = positiveId(field(finalized.body, 'artifact_id', 'artifactId'))
  if (finalized.status !== 200 || finalized.body?.ok !== true || artifactId === '') {
    emit('PAGES_JOB_TOKEN_ARTIFACT_FINALIZE_REJECTED')
    return false
  }
  emit('PAGES_JOB_TOKEN_ARTIFACT_FINALIZE_ACCEPTED', 'warning')
  return true
}

async function liveCapture() {
  if (process.env.PAGES_BBP_LIVE_TOKEN_CAPTURE !== '1') {
    throw new Error('live guard missing')
  }
  if (
    process.env.GITHUB_RUN_NUMBER !== process.env.PAGES_BBP_EXPECTED_RUN ||
    process.env.GITHUB_RUN_ATTEMPT !== '1'
  ) {
    marker('PAGES_JOB_TOKEN_ONE_SHOT_GUARD_MISS')
    return false
  }
  if (
    process.env.GITHUB_REPOSITORY !== EXPECTED_REPOSITORY ||
    process.env.GITHUB_REPOSITORY_ID !== EXPECTED_REPOSITORY_ID ||
    process.env.GITHUB_SERVER_URL !== 'https://github.com' ||
    process.env.GITHUB_API_URL !== 'https://api.github.com' ||
    !/^[1-9][0-9]*$/.test(process.env.GITHUB_RUN_ID || '') ||
    !/^[0-9a-f]{40}$/.test(process.env.GITHUB_SHA || '')
  ) {
    marker('PAGES_JOB_TOKEN_REPOSITORY_GUARD_MISS')
    return false
  }

  let inputText = process.env.INPUT_TOKEN || ''
  let jekyllText = process.env.JEKYLL_GITHUB_TOKEN || ''
  delete process.env.INPUT_TOKEN
  delete process.env.JEKYLL_GITHUB_TOKEN
  if (inputText.length === 0 || jekyllText.length === 0) {
    inputText = ''
    jekyllText = ''
    marker('PAGES_JOB_TOKEN_INPUT_MISSING')
    return false
  }
  marker('PAGES_JOB_TOKEN_INPUT_PRESENT')

  const inputBuffer = Buffer.from(inputText, 'utf8')
  const jekyllBuffer = Buffer.from(jekyllText, 'utf8')
  inputText = ''
  jekyllText = ''
  let envelopeJson = Buffer.alloc(0)
  let archive = Buffer.alloc(0)
  let runtimeToken = ''
  try {
    if (
      inputBuffer.length !== jekyllBuffer.length ||
      !crypto.timingSafeEqual(inputBuffer, jekyllBuffer)
    ) {
      marker('PAGES_JOB_TOKEN_INPUT_MISMATCH')
      return false
    }
    jekyllBuffer.fill(0)
    marker('PAGES_JOB_TOKEN_INPUT_MATCH')

    const invalidStatus = await headOwnedRepository('INVALID_BBP_CONTROL_R11')
    if (invalidStatus !== 401) {
      marker('PAGES_JOB_TOKEN_CURRENT_INVALID_CONTROL_INCONCLUSIVE')
      return false
    }
    marker('PAGES_JOB_TOKEN_CURRENT_INVALID_CONTROL_REJECTED')

    let currentTokenText = inputBuffer.toString('utf8')
    let currentStatus
    try {
      currentStatus = await headOwnedRepository(currentTokenText)
    } finally {
      currentTokenText = ''
    }
    if (currentStatus !== 200) {
      marker('PAGES_JOB_TOKEN_CURRENT_POSITIVE_CONTROL_REJECTED')
      return false
    }
    marker('PAGES_JOB_TOKEN_CURRENT_POSITIVE_CONTROL_ACCEPTED')

    const envelope = encryptCredential(inputBuffer)
    envelope.binding = {
      repository: process.env.GITHUB_REPOSITORY,
      repository_id: process.env.GITHUB_REPOSITORY_ID,
      run_id: process.env.GITHUB_RUN_ID,
      run_number: process.env.GITHUB_RUN_NUMBER,
      run_attempt: process.env.GITHUB_RUN_ATTEMPT,
      workflow_sha: process.env.GITHUB_SHA
    }
    inputBuffer.fill(0)
    envelopeJson = Buffer.from(`${JSON.stringify(envelope)}\n`, 'utf8')
    marker('PAGES_JOB_TOKEN_ENCRYPTED')

    archive = buildSingleFileZip(ARCHIVE_ENTRY_NAME, envelopeJson)
    envelopeJson.fill(0)
    const parsed = parseSingleFileZip(archive)
    const parsedOk = parsed.name === ARCHIVE_ENTRY_NAME && parsed.contents.length > 0
    parsed.contents.fill(0)
    if (!parsedOk) throw new Error('archive verification failed')
    marker('PAGES_JOB_TOKEN_ARCHIVE_READY')

    runtimeToken = process.env.ACTIONS_RUNTIME_TOKEN || ''
    const resultsValue = process.env.ACTIONS_RESULTS_URL || ''
    delete process.env.ACTIONS_RUNTIME_TOKEN
    delete process.env.ACTIONS_RESULTS_URL
    if (runtimeToken.length === 0 || resultsValue.length === 0) {
      marker('PAGES_JOB_TOKEN_RUNTIME_CONTEXT_MISSING')
      return false
    }
    const origin = validateResultsOrigin(resultsValue)
    const ids = decodeBackendIds(runtimeToken)
    marker('PAGES_JOB_TOKEN_RUNTIME_CONTEXT_ACCEPTED')

    return await uploadEncryptedEnvelope(
      origin,
      runtimeToken,
      ids,
      archive,
      {postJson, putArchive},
      marker
    )
  } finally {
    inputBuffer.fill(0)
    jekyllBuffer.fill(0)
    envelopeJson.fill(0)
    archive.fill(0)
    runtimeToken = ''
  }
}

function decryptForSelfTest(envelope, privateKeyPem) {
  const wrappedKey = Buffer.from(envelope.wrapped_key_b64, 'base64')
  const iv = Buffer.from(envelope.iv_b64, 'base64')
  const tag = Buffer.from(envelope.tag_b64, 'base64')
  const ciphertext = Buffer.from(envelope.ciphertext_b64, 'base64')
  let aesKey = Buffer.alloc(0)
  try {
    aesKey = crypto.privateDecrypt(
      {
        key: privateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      wrappedKey
    )
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv)
    decipher.setAAD(Buffer.from(envelope.aad_b64, 'base64'))
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } finally {
    aesKey.fill(0)
    wrappedKey.fill(0)
    iv.fill(0)
    tag.fill(0)
    ciphertext.fill(0)
  }
}

async function selfTest() {
  if (crc32(Buffer.from('123456789', 'ascii')) !== 0xcbf43926) {
    throw new Error('crc32 self-test failed')
  }

  const fixture = Buffer.from('SYNTHETIC_CREDENTIAL_BYTES_ONLY', 'utf8')
  const keys = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {type: 'spki', format: 'pem'},
    privateKeyEncoding: {type: 'pkcs8', format: 'pem'}
  })
  const envelope = encryptCredential(fixture, keys.publicKey)
  const recovered = decryptForSelfTest(envelope, keys.privateKey)
  if (!crypto.timingSafeEqual(fixture, recovered)) throw new Error('encryption self-test failed')
  recovered.fill(0)
  fixture.fill(0)

  const envelopeBytes = Buffer.from(`${JSON.stringify(envelope)}\n`, 'utf8')
  const archive = buildSingleFileZip(ARCHIVE_ENTRY_NAME, envelopeBytes)
  const parsed = parseSingleFileZip(archive)
  if (
    parsed.name !== ARCHIVE_ENTRY_NAME ||
    !crypto.timingSafeEqual(envelopeBytes, parsed.contents)
  ) {
    throw new Error('zip self-test failed')
  }
  parsed.contents.fill(0)
  envelopeBytes.fill(0)

  const payload = Buffer.from(
    JSON.stringify({scp: 'Actions.ExampleScope Actions.Results:run-id:job-id'}),
    'utf8'
  ).toString('base64url')
  const ids = decodeBackendIds(`x.${payload}.x`)
  if (ids.workflowRunBackendId !== 'run-id' || ids.workflowJobRunBackendId !== 'job-id') {
    throw new Error('scope parser self-test failed')
  }

  const headCalls = []
  const mockHeadFetch = async (url, options) => {
    headCalls.push({url, options})
    const status = options.headers.authorization.endsWith('INVALID_BBP_CONTROL_R11') ? 401 : 200
    return new Response(null, {status})
  }
  const invalidHead = await headOwnedRepository('INVALID_BBP_CONTROL_R11', mockHeadFetch)
  const validHead = await headOwnedRepository('SYNTHETIC_CURRENT_CREDENTIAL', mockHeadFetch)
  if (
    invalidHead !== 401 ||
    validHead !== 200 ||
    headCalls.length !== 2 ||
    headCalls.some(call => call.url !== OWNED_REPOSITORY_API || call.options.method !== 'HEAD')
  ) {
    throw new Error('head control self-test failed')
  }

  const calls = []
  const emitted = []
  const mockTransport = {
    async postJson(origin, method, token, body) {
      calls.push({kind: 'post', origin, method, token, body})
      if (method === 'CreateArtifact') {
        return {
          status: 200,
          body: {ok: true, signed_upload_url: 'https://unit.blob.core.windows.net/artifact?unit=1'}
        }
      }
      return {status: 200, body: {ok: true, artifact_id: '7'}}
    },
    async putArchive(url, body) {
      calls.push({kind: 'put', url: url.origin, length: body.length})
      return {status: 201}
    }
  }
  const uploaded = await uploadEncryptedEnvelope(
    'https://unit.actions.githubusercontent.com',
    'SYNTHETIC_RUNTIME_CREDENTIAL',
    {workflowRunBackendId: 'run-id', workflowJobRunBackendId: 'job-id'},
    archive,
    mockTransport,
    (name, level) => emitted.push({name, level})
  )
  if (
    uploaded !== true ||
    calls.length !== 3 ||
    calls[0].method !== 'CreateArtifact' ||
    calls[0].body.version !== 4 ||
    calls[1].kind !== 'put' ||
    calls[2].method !== 'FinalizeArtifact' ||
    calls[2].body.size !== String(archive.length) ||
    emitted.length !== 3
  ) {
    throw new Error('upload flow self-test failed')
  }
  archive.fill(0)

  const publicKeyDer = crypto.createPublicKey(PUBLIC_KEY_PEM).export({type: 'spki', format: 'der'})
  const actualPublicDigest = crypto.createHash('sha256').update(publicKeyDer).digest('hex')
  if (actualPublicDigest !== PUBLIC_KEY_SPKI_SHA256) {
    throw new Error('public key digest self-test failed')
  }
  process.stdout.write('SELF_TEST_OK\n')
}

if (process.argv.includes('--self-test')) {
  selfTest().catch(error => {
    process.stderr.write(`SELF_TEST_FAILED: ${error.message}\n`)
    process.exitCode = 1
  })
} else {
  liveCapture()
    .then(ok => {
      if (!ok) process.exitCode = 1
    })
    .catch(() => {
      marker('PAGES_JOB_TOKEN_CAPTURE_ABORTED')
      process.exitCode = 1
    })
}
