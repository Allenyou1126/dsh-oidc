/** Local OIDC provider used by the plugin tests. It is not part of the shipped bundle. */
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import { createServer } from 'node:http'

function base64url(value) {
  return Buffer.from(value).toString('base64url')
}

async function readBody(request) {
  const chunks = []
  for await (const chunk of request) chunks.push(chunk)
  return Buffer.concat(chunks).toString('utf8')
}

function sendJson(response, value, status = 200) {
  const body = JSON.stringify(value)
  response.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
  })
  response.end(body)
}

/**
 * Start an OIDC provider that speaks the public-client / PKCE subset used by DSH.
 * @returns the provider URL and test controls.
 */
export async function createMockIdp({ clientId = 'test-client' } = {}) {
  let signing = generateKeyPairSync('rsa', { modulusLength: 2048 })
  let signingKid = 'k1'
  let nextKid = 2
  let keys = [{ ...signing.publicKey.export({ format: 'jwk' }), kid: signingKid, alg: 'RS256', use: 'sig' }]
  const codes = new Map()
  const requests = []
  let discovery

  function issueCode({ nonce, challenge, claims = {}, nonceOverride } = {}) {
    const code = randomBytes(16).toString('base64url')
    codes.set(code, { nonce, challenge, claims, nonceOverride })
    return code
  }

  function signIdToken(payload) {
    const header = { alg: 'RS256', typ: 'JWT', kid: signingKid }
    const input = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`
    const signature = sign('RSA-SHA256', Buffer.from(input, 'utf8'), signing.privateKey)
    return `${input}.${signature.toString('base64url')}`
  }

  function rotate() {
    signing = generateKeyPairSync('rsa', { modulusLength: 2048 })
    signingKid = `k${nextKid++}`
    keys = [{ ...signing.publicKey.export({ format: 'jwk' }), kid: signingKid, alg: 'RS256', use: 'sig' }]
  }

  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', 'http://mock.invalid')
    if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
      sendJson(response, discovery)
      return
    }
    if (request.method === 'GET' && url.pathname === '/jwks') {
      sendJson(response, { keys })
      return
    }
    if (request.method === 'GET' && url.pathname === '/authorize') {
      const redirect = new URL(url.searchParams.get('redirect_uri'))
      const code = issueCode({
        nonce: url.searchParams.get('nonce') ?? undefined,
        challenge: url.searchParams.get('code_challenge') ?? undefined,
      })
      redirect.searchParams.set('code', code)
      redirect.searchParams.set('state', url.searchParams.get('state') ?? '')
      response.writeHead(302, { location: redirect.href })
      response.end()
      return
    }
    if (request.method === 'POST' && url.pathname === '/token') {
      const body = await readBody(request)
      requests.push({ path: url.pathname, headers: request.headers, body })
      if (request.headers.authorization !== undefined) {
        sendJson(response, { error: 'invalid_client', error_description: 'public client must not authenticate' }, 401)
        return
      }
      const form = new URLSearchParams(body)
      const code = codes.get(form.get('code') ?? '')
      if (code === undefined) {
        sendJson(response, { error: 'invalid_grant' }, 400)
        return
      }
      if (form.get('grant_type') !== 'authorization_code'
        || form.get('client_id') !== clientId
        || form.get('redirect_uri') === null
        || form.get('code_verifier') === null) {
        sendJson(response, { error: 'invalid_request' }, 400)
        return
      }
      const verifier = form.get('code_verifier')
      const challenge = base64url(createHash('sha256').update(verifier).digest())
      if (code.challenge !== undefined && challenge !== code.challenge) {
        sendJson(response, { error: 'invalid_grant', error_description: 'PKCE verification failed' }, 400)
        return
      }
      codes.delete(form.get('code'))
      const now = Math.floor(Date.now() / 1000)
      const payload = {
        ...code.claims,
        iss: base,
        aud: clientId,
        sub: code.claims.sub ?? 'user-1',
        iat: now,
        exp: now + 300,
        nonce: code.nonceOverride ?? code.nonce,
      }
      sendJson(response, {
        access_token: 'mock-access-token',
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: signIdToken(payload),
      })
      return
    }
    response.writeHead(404)
    response.end()
  })

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject)
      resolve()
    })
  })
  const address = server.address()
  const base = `http://127.0.0.1:${address.port}`
  discovery = {
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    jwks_uri: `${base}/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
  }

  return {
    base,
    clientId,
    issueCode,
    rotate,
    requests,
    close: async () => {
      server.closeAllConnections?.()
      await new Promise(resolve => server.close(resolve))
    },
  }
}
