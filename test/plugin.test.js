import assert from 'node:assert/strict'
import test from 'node:test'
import { apply } from '../src/plugin.js'
import { createMockIdp } from './mock-idp.js'

const BASE = 'http://127.0.0.1:3080/'
const HOST = '127.0.0.1:3080'
const CLIENT_ID = 'test-client'

class FakeResponse {
  constructor() {
    this.statusCode = 200
    this.headers = {}
    this.body = undefined
    this.ended = false
    this.headersSent = false
    this.destroyed = false
  }

  setHeader(name, value) {
    this.headers[name.toLowerCase()] = value
  }

  getHeader(name) {
    return this.headers[name.toLowerCase()]
  }

  writeHead(status, headers = {}) {
    this.statusCode = status
    for (const [name, value] of Object.entries(headers)) this.setHeader(name, value)
    this.headersSent = true
    return this
  }

  end(body) {
    this.body = body
    this.ended = true
    this.headersSent = true
  }

  destroy() {
    this.destroyed = true
  }

  get setCookies() {
    const value = this.headers['set-cookie']
    if (value === undefined) return []
    return Array.isArray(value) ? value : [value]
  }
}

function makeRequest({ method = 'GET', url = '/', headers = {} } = {}) {
  return {
    method,
    url,
    headers: { host: HOST, ...headers },
    socket: { destroyed: false },
    on() {},
  }
}

function createContext({ advertisedUrl = BASE } = {}) {
  const listeners = new Map()
  const logs = []
  const controller = new AbortController()
  let provider
  const peer = {
    id: 'peer',
    principal: { kind: 'owner' },
    signal: controller.signal,
    ctx: { effect() {} },
    dispose: async () => { controller.abort() },
  }
  const ctx = {
    logger: {
      info: message => logs.push(['info', String(message)]),
      warn: message => logs.push(['warn', String(message)]),
      error: message => logs.push(['error', String(message)]),
    },
    on(event, listener) {
      const list = listeners.get(event) ?? []
      list.push(listener)
      listeners.set(event, list)
      return () => {}
    },
    connection: {
      createPeer: () => peer,
      authentication: {
        register(candidate) {
          provider = candidate
          return async () => { provider = undefined }
        },
        authenticate(request) {
          const authenticated = provider?.authenticate(request)
          return authenticated === undefined ? { rejection: 401 } : { peer: authenticated }
        },
      },
    },
    webApp: { getAdvertisedUrl: () => advertisedUrl },
    webServer: { protocol: advertisedUrl.startsWith('https:') ? 'https:' : 'http:' },
  }
  return {
    ctx,
    logs,
    peer,
    get provider() { return provider },
    get hasMiddleware() { return listeners.has('webserver/request') },
    async dispatch(request, response) {
      const listener = listeners.get('webserver/request')?.[0]
      if (listener === undefined) return { handled: false, nextCalled: false }
      let nextCalled = false
      await listener(request, response, async () => { nextCalled = true })
      return { handled: true, nextCalled }
    },
    dispose() {
      controller.abort()
    },
  }
}

function cookieValue(response, name) {
  const header = response.setCookies.find(value => value.startsWith(`${name}=`))
  if (header === undefined) return undefined
  return header.slice(name.length + 1).split(';')[0].trim()
}

function completionTarget(response) {
  const match = /location\.replace\((".*?")\)/u.exec(String(response.body))
  return match === null ? undefined : JSON.parse(match[1])
}

async function beginLogin(app, { returnTo = '/' } = {}) {
  const startResponse = new FakeResponse()
  const start = await app.dispatch(makeRequest({
    url: '/',
    headers: { accept: 'text/html' },
  }), startResponse)
  assert.equal(start.handled, true)
  assert.equal(start.nextCalled, false)
  assert.equal(startResponse.statusCode, 302)
  const loginLocation = new URL(startResponse.headers.location)
  assert.equal(loginLocation.pathname, '/auth/login')
  assert.equal(loginLocation.searchParams.get('returnTo'), returnTo)

  const loginResponse = new FakeResponse()
  const login = await app.dispatch(makeRequest({
    url: `${loginLocation.pathname}${loginLocation.search}`,
    headers: { accept: 'text/html' },
  }), loginResponse)
  assert.equal(login.nextCalled, false)
  assert.equal(loginResponse.statusCode, 302)
  const authorize = new URL(loginResponse.headers.location)
  const stateCookie = cookieValue(loginResponse, 'dsh-oidc-state')
  assert.ok(stateCookie)
  return {
    startResponse,
    loginResponse,
    authorize,
    stateCookie,
    state: authorize.searchParams.get('state'),
    nonce: authorize.searchParams.get('nonce'),
    challenge: authorize.searchParams.get('code_challenge'),
  }
}

async function finishLogin(app, mock, {
  claims = {},
  nonceOverride,
  begun = undefined,
} = {}) {
  const started = begun ?? await beginLogin(app)
  const code = mock.issueCode({
    nonce: started.nonce,
    challenge: started.challenge,
    claims,
    nonceOverride,
  })
  const response = new FakeResponse()
  const dispatch = await app.dispatch(makeRequest({
    url: `/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(started.state)}`,
    headers: {
      accept: 'text/html',
      cookie: `dsh-oidc-state=${started.stateCookie}`,
      'sec-fetch-site': 'cross-site',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-dest': 'document',
    },
  }), response)
  return { started, code, response, dispatch }
}

async function activeApp(t, { config = {}, env = {} } = {}) {
  const mock = await createMockIdp({ clientId: CLIENT_ID })
  t.after(() => mock.close())
  const app = createContext()
  apply(app.ctx, {
    issuer: mock.base,
    clientId: CLIENT_ID,
    scopes: ['openid'],
    ...config,
  }, env)
  return { app, mock }
}

test('inactive configuration registers no middleware or provider', async () => {
  const app = createContext()
  apply(app.ctx, {}, {})
  assert.equal(app.hasMiddleware, false)
  assert.equal(app.provider, undefined)
  assert.match(app.logs[0][1], /inactive/u)
  const response = new FakeResponse()
  const result = await app.dispatch(makeRequest({ url: '/', headers: { accept: 'text/html' } }), response)
  assert.equal(result.handled, false)
  assert.equal(response.statusCode, 200)
})

test('an index request without HTML markers still starts sign-in', async (t) => {
  const { app } = await activeApp(t)
  const response = new FakeResponse()
  const result = await app.dispatch(makeRequest({
    url: '/',
    headers: { 'sec-fetch-site': 'cross-site' },
  }), response)
  assert.equal(result.handled, true)
  assert.equal(result.nextCalled, false)
  assert.equal(response.statusCode, 302)
  assert.equal(new URL(response.headers.location).pathname, '/auth/login')
})

test('complete public-client login, provider authentication, index pass-through, and logout', async (t) => {
  const { app, mock } = await activeApp(t)
  const { response, started } = await finishLogin(app, mock, { claims: { sub: 'user-1' } })

  assert.equal(response.statusCode, 200)
  assert.equal(completionTarget(response), `${BASE}`)
  const sessionCookie = cookieValue(response, 'dsh-oidc-session')
  assert.ok(sessionCookie)
  assert.equal(cookieValue(response, 'dsh-oidc-state'), '')

  const peer = app.provider.authenticate({
    headers: { host: HOST, cookie: `dsh-oidc-session=${sessionCookie}` },
  })
  assert.equal(peer, app.peer)

  const indexResponse = new FakeResponse()
  const index = await app.dispatch(makeRequest({
    url: '/',
    headers: { accept: 'text/html', cookie: `dsh-oidc-session=${sessionCookie}` },
  }), indexResponse)
  assert.equal(index.nextCalled, true)

  const tokenRequest = mock.requests.find(request => request.path === '/token')
  assert.ok(tokenRequest)
  assert.equal(tokenRequest.headers.authorization, undefined)
  const form = new URLSearchParams(tokenRequest.body)
  assert.equal(form.get('client_id'), CLIENT_ID)
  assert.ok(form.get('code_verifier'))
  assert.equal(form.get('redirect_uri'), `${BASE}auth/callback`)
  assert.equal(started.authorize.searchParams.get('code_challenge_method'), 'S256')
  assert.equal(started.authorize.searchParams.get('client_id'), CLIENT_ID)

  const logoutResponse = new FakeResponse()
  const logout = await app.dispatch(makeRequest({
    url: '/auth/logout',
    headers: {
      accept: 'text/html',
      cookie: `dsh-oidc-session=${sessionCookie}`,
      'sec-fetch-site': 'same-origin',
    },
  }), logoutResponse)
  assert.equal(logout.nextCalled, false)
  assert.equal(logoutResponse.statusCode, 200)
  assert.equal(cookieValue(logoutResponse, 'dsh-oidc-session'), '')
  assert.equal(completionTarget(logoutResponse), `${BASE}`)
})

test('access uses the configured role claim and rejects missing or unmatched roles', async (t) => {
  const { app, mock } = await activeApp(t, {
    config: { roleClaim: 'roles', allowedRoles: ['dsh-owner'] },
  })

  const denied = await finishLogin(app, mock, { claims: { roles: ['viewer'] } })
  assert.equal(denied.response.statusCode, 403)
  assert.equal(cookieValue(denied.response, 'dsh-oidc-session'), undefined)

  const allowed = await finishLogin(app, mock, { claims: { roles: ['dsh-owner'] } })
  assert.equal(allowed.response.statusCode, 200)
  assert.ok(cookieValue(allowed.response, 'dsh-oidc-session'))

  const missing = await finishLogin(app, mock, { claims: {} })
  assert.equal(missing.response.statusCode, 403)
})

test('a Zitadel role object is read through object keys', async (t) => {
  const claim = 'urn:zitadel:iam:org:project:roles'
  const { app, mock } = await activeApp(t, {
    config: { roleClaim: claim, allowedRoles: ['dsh-owner'] },
  })
  const result = await finishLogin(app, mock, {
    claims: { [claim]: { 'dsh-owner': { 'org-id': 'acme' } } },
  })
  assert.equal(result.response.statusCode, 200)
  assert.ok(cookieValue(result.response, 'dsh-oidc-session'))
})

test('roleClaim present with no allowedRoles requires any role value', async (t) => {
  const { app, mock } = await activeApp(t, {
    config: { roleClaim: 'roles', allowedRoles: [] },
  })
  const anyRole = await finishLogin(app, mock, { claims: { roles: ['anything'] } })
  assert.equal(anyRole.response.statusCode, 200)

  const noRole = await finishLogin(app, mock, { claims: { roles: [] } })
  assert.equal(noRole.response.statusCode, 403)
})

test('ID tokens without an email claim are accepted', async (t) => {
  const { app, mock } = await activeApp(t)
  const result = await finishLogin(app, mock, { claims: { sub: 'no-email-user' } })
  assert.equal(result.response.statusCode, 200)
})

test('a rotated JWKS key is refreshed once for an unknown kid', async (t) => {
  const { app, mock } = await activeApp(t)
  const first = await finishLogin(app, mock, { claims: { sub: 'user-1' } })
  assert.equal(first.response.statusCode, 200)

  mock.rotate()
  const second = await finishLogin(app, mock, { claims: { sub: 'user-1' } })
  assert.equal(second.response.statusCode, 200)
  assert.ok(cookieValue(second.response, 'dsh-oidc-session'))
})

test('callback rejects a non-public host and a mismatched state', async (t) => {
  const { app, mock } = await activeApp(t)
  const started = await beginLogin(app)
  const code = mock.issueCode({ nonce: started.nonce, challenge: started.challenge })

  const badHost = new FakeResponse()
  await app.dispatch(makeRequest({
    url: `/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(started.state)}`,
    headers: {
      host: 'evil.example:3080',
      cookie: `dsh-oidc-state=${started.stateCookie}`,
      'sec-fetch-site': 'cross-site',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-dest': 'document',
    },
  }), badHost)
  assert.equal(badHost.statusCode, 403)

  const wrongState = new FakeResponse()
  await app.dispatch(makeRequest({
    url: `/auth/callback?code=${encodeURIComponent(code)}&state=wrong`,
    headers: {
      cookie: `dsh-oidc-state=${started.stateCookie}`,
      'sec-fetch-site': 'cross-site',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-dest': 'document',
    },
  }), wrongState)
  assert.equal(wrongState.statusCode, 400)
})

test('cross-site logout is refused', async (t) => {
  const { app } = await activeApp(t)
  const response = new FakeResponse()
  const result = await app.dispatch(makeRequest({
    url: '/auth/logout',
    headers: { accept: 'text/html', 'sec-fetch-site': 'cross-site' },
  }), response)
  assert.equal(result.nextCalled, false)
  assert.equal(response.statusCode, 403)
})
