/**
 * Minimal OIDC SSO for the DSH Web carrier.
 *
 * The IdP callback is a cross-site top-level navigation, which DSH's browser
 * trust fence refuses on registered routes. Every OIDC endpoint is therefore
 * handled in the `webserver/request` waterfall before route admission, with its
 * own Host/state/nonce checks. After login, a same-origin completion page sends
 * the browser to the application so the next navigation passes that fence.
 */
import { createHash } from 'node:crypto'
import { isLoopbackHostname, resolveConfig } from './config.js'
import {
  clearCookie,
  randomToken,
  readCookie,
  serializeCookie,
  signPayload,
  verifyPayload,
} from './cookies.js'
import { OidcClient } from './oidc.js'

const LOGIN_PATH = '/auth/login'
const CALLBACK_PATH = '/auth/callback'
const LOGOUT_PATH = '/auth/logout'
const SESSION_COOKIE = 'dsh-oidc-session'
const STATE_COOKIE = 'dsh-oidc-state'
const SESSION_TTL_MS = 12 * 60 * 60 * 1000
const STATE_TTL_MS = 10 * 60 * 1000
const SESSION_MAX_AGE_SECONDS = SESSION_TTL_MS / 1000
const STATE_MAX_AGE_SECONDS = STATE_TTL_MS / 1000

function headerValue(headers, name) {
  if (headers instanceof Headers) return headers.get(name) ?? undefined
  if (headers === null || typeof headers !== 'object') return undefined
  const value = headers[name] ?? headers[name.toLowerCase()]
  if (Array.isArray(value)) return value[0]
  return typeof value === 'string' ? value : undefined
}

function requestHost(headers, base) {
  const raw = headerValue(headers, 'host')
  if (raw === undefined || raw === '') return undefined
  try {
    return new URL(`${base.protocol}//${raw}`).host
  } catch {
    return undefined
  }
}

function isIndexPath(pathname) {
  return pathname === '/' || pathname === '/index.html'
}

function wantsHtml(headers) {
  if (headerValue(headers, 'sec-fetch-dest') === 'document') return true
  return (headerValue(headers, 'accept') ?? '').includes('text/html')
}

function isNavigation(headers, base) {
  const origin = headerValue(headers, 'origin')
  if (origin !== undefined && origin !== base.origin) return false
  const mode = headerValue(headers, 'sec-fetch-mode')
  if (mode !== undefined && mode !== 'navigate') return false
  const destination = headerValue(headers, 'sec-fetch-dest')
  if (destination !== undefined && destination !== 'document') return false
  return true
}

function sanitizeReturnTo(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return '/'
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return '/'
  // Control characters cannot appear in a safe Location/HTML target.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/u.test(value)) return '/'
  return value
}

function appUrl(base, returnTo) {
  const safe = sanitizeReturnTo(returnTo)
  const at = safe.indexOf('?')
  const path = at === -1 ? safe : safe.slice(0, at)
  const query = at === -1 ? undefined : safe.slice(at + 1)
  const relative = path === '/' || path === '/index.html' ? './' : `.${path}`
  return new URL(relative + (query === undefined ? '' : `?${query}`), base).href
}

function authUrl(base, endpoint) {
  return new URL(`auth/${endpoint}`, base).href
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function withCookies(headers, cookies) {
  if (cookies.length === 1) headers['set-cookie'] = cookies[0]
  else if (cookies.length > 1) headers['set-cookie'] = cookies
  return headers
}

function sendRedirect(res, location, cookies = [], status = 302) {
  res.writeHead(status, withCookies({
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    location,
  }, cookies))
  res.end()
}

function sendHtml(res, status, html, { cookies = [], head = false, headers = {} } = {}) {
  res.writeHead(status, withCookies({
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    ...headers,
  }, cookies))
  res.end(head ? undefined : html)
}

function sendError(res, status, message, { retryUrl, cookies = [], head = false } = {}) {
  const link = retryUrl === undefined ? '' : `<p><a href="${escapeHtml(retryUrl)}">Try again</a></p>`
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>OIDC sign-in</title></head><body><p>${escapeHtml(message)}</p>${link}</body></html>`
  sendHtml(res, status, html, {
    cookies,
    head,
    headers: { 'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'" },
  })
}

function sendCompletion(res, target, cookies, head = false) {
  const nonce = randomToken(16)
  const jsonTarget = JSON.stringify(target)
    .replaceAll('<', '\\u003c')
    .replaceAll('\u2028', '\\u2028')
    .replaceAll('\u2029', '\\u2029')
  const htmlTarget = escapeHtml(target)
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Signing in…</title></head><body><p>Signing in…</p><script nonce="${nonce}">location.replace(${jsonTarget})</script><noscript><meta http-equiv="refresh" content="0; url=${htmlTarget}"></noscript><p><a href="${htmlTarget}">Continue</a></p></body></html>`
  sendHtml(res, 200, html, {
    cookies,
    head,
    headers: {
      'content-security-policy': `default-src 'none'; script-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'`,
    },
  })
}

function getClaim(claims, path) {
  if (Object.prototype.hasOwnProperty.call(claims, path)) return claims[path]
  let current = claims
  for (const part of path.split('.')) {
    if (current === null || typeof current !== 'object' || !Object.prototype.hasOwnProperty.call(current, part)) {
      return undefined
    }
    current = current[part]
  }
  return current
}

function normalizeRoles(value) {
  if (Array.isArray(value)) return value.filter(role => typeof role === 'string' && role !== '')
  if (typeof value === 'string') return value === '' ? [] : [value]
  if (value !== null && typeof value === 'object') return Object.keys(value)
  return []
}

function roleAccess(claims, config) {
  if (config.roleClaim === '') return { allowed: true, reason: 'no role claim configured' }
  const roles = normalizeRoles(getClaim(claims, config.roleClaim))
  if (roles.length === 0) return { allowed: false, reason: `claim ${config.roleClaim} is missing or empty` }
  if (config.allowedRoles.length === 0) return { allowed: true, reason: 'role claim present' }
  const allowed = roles.some(role => config.allowedRoles.includes(role))
  return allowed
    ? { allowed: true, reason: 'role matched' }
    : { allowed: false, reason: `no role matched ${config.roleClaim}` }
}

/**
 * Register the OIDC provider and its request middleware.
 * @param ctx - plugin context with connection, authentication, webServer, webApp.
 * @param rawConfig - validated Config values.
 * @param env - environment source; tests inject a bare object.
 */
export function apply(ctx, rawConfig, env = process.env) {
  const config = resolveConfig(rawConfig, env)
  if (!config.active) {
    ctx.logger.info(`dsh-oidc: inactive (${config.reason})`)
    return
  }

  const secret = randomToken(32)
  const peer = ctx.connection.createPeer({ principal: { kind: 'owner' } })
  const oidc = new OidcClient({
    issuer: config.issuer,
    clientId: config.clientId,
    scopes: config.scopes,
  })
  let baseCache

  function base() {
    if (baseCache !== undefined) return baseCache
    const url = new URL(ctx.webApp.getAdvertisedUrl())
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopbackHostname(url.hostname))) {
      throw new Error('public URL must use HTTPS (HTTP is allowed only on a loopback address)')
    }
    url.search = ''
    url.hash = ''
    if (!url.pathname.endsWith('/')) url.pathname = `${url.pathname}/`
    baseCache = url
    return url
  }

  function secure() {
    return base().protocol === 'https:'
  }

  function hostMatches(headers) {
    return requestHost(headers, base()) === base().host
  }

  function retryUrl() {
    return authUrl(base(), 'login')
  }

  function authenticate(request) {
    if (peer.signal.aborted) return undefined
    let baseUrl
    try {
      baseUrl = base()
    } catch {
      return undefined
    }
    if (requestHost(request.headers, baseUrl) !== baseUrl.host) return undefined
    const cookie = readCookie(headerValue(request.headers, 'cookie'), SESSION_COOKIE)
    const payload = verifyPayload(secret, cookie, {
      maxAgeMs: SESSION_TTL_MS,
      host: baseUrl.host,
    })
    if (payload === undefined || typeof payload.sub !== 'string' || payload.sub === '') return undefined
    return peer
  }

  async function handleLogin(req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      sendError(res, 405, 'Method not allowed.', { head: req.method === 'HEAD' })
      return
    }
    if (!hostMatches(req.headers)) {
      sendError(res, 403, 'Request host is not the configured public host.', { head: req.method === 'HEAD' })
      return
    }
    const url = new URL(req.url ?? '/', 'http://dsh.invalid')
    const returnTo = sanitizeReturnTo(url.searchParams.get('returnTo'))
    let discovery
    try {
      discovery = await oidc.discovery()
    } catch (error) {
      ctx.logger.warn(`dsh-oidc: discovery failed: ${error instanceof Error ? error.message : String(error)}`)
      sendError(res, 502, 'The identity provider is unavailable.', {
        head: req.method === 'HEAD',
        retryUrl: authUrl(base(), 'login'),
      })
      return
    }
    const state = randomToken(32)
    const nonce = randomToken(32)
    const verifier = randomToken(32)
    const challenge = createHash('sha256').update(verifier).digest('base64url')
    const now = Date.now()
    const stateCookie = serializeCookie(STATE_COOKIE, signPayload(secret, {
      s: state,
      n: nonce,
      vf: verifier,
      r: returnTo,
      h: base().host,
      iat: now,
      exp: now + STATE_TTL_MS,
    }), {
      maxAgeSeconds: STATE_MAX_AGE_SECONDS,
      secure: secure(),
    })
    const authorization = new URL(discovery.authorization_endpoint)
    authorization.searchParams.set('response_type', 'code')
    authorization.searchParams.set('client_id', config.clientId)
    authorization.searchParams.set('redirect_uri', authUrl(base(), 'callback'))
    authorization.searchParams.set('scope', config.scopes.join(' '))
    authorization.searchParams.set('state', state)
    authorization.searchParams.set('nonce', nonce)
    authorization.searchParams.set('code_challenge', challenge)
    authorization.searchParams.set('code_challenge_method', 'S256')
    sendRedirect(res, authorization.href, [stateCookie])
  }

  async function handleCallback(req, res) {
    if (req.method !== 'GET') {
      sendError(res, 405, 'Method not allowed.', { head: req.method === 'HEAD' })
      return
    }
    if (!hostMatches(req.headers)) {
      sendError(res, 403, 'Request host is not the configured public host.', { head: req.method === 'HEAD' })
      return
    }
    if (!isNavigation(req.headers, base())) {
      sendError(res, 403, 'The sign-in callback must be a top-level navigation.', { head: req.method === 'HEAD' })
      return
    }
    const url = new URL(req.url ?? '/', 'http://dsh.invalid')
    const clearState = clearCookie(STATE_COOKIE, { secure: secure() })
    const statePayload = verifyPayload(secret, readCookie(headerValue(req.headers, 'cookie'), STATE_COOKIE), {
      maxAgeMs: STATE_TTL_MS,
      host: base().host,
    })
    const queryState = url.searchParams.get('state')
    if (statePayload === undefined
      || typeof statePayload.s !== 'string'
      || typeof statePayload.n !== 'string'
      || typeof statePayload.vf !== 'string'
      || typeof statePayload.r !== 'string'
      || queryState === null
      || statePayload.s !== queryState) {
      sendError(res, 400, 'The sign-in session expired; start again.', {
        head: req.method === 'HEAD',
        cookies: [clearState],
        retryUrl: authUrl(base(), 'login'),
      })
      return
    }
    if (url.searchParams.has('error')) {
      ctx.logger.warn(`dsh-oidc: identity provider returned ${url.searchParams.get('error') ?? 'an error'}`)
      sendError(res, 403, 'Sign-in was cancelled or denied by the identity provider.', {
        head: req.method === 'HEAD',
        cookies: [clearState],
        retryUrl: authUrl(base(), 'login'),
      })
      return
    }
    const code = url.searchParams.get('code')
    if (code === null || code === '') {
      sendError(res, 400, 'The sign-in callback has no authorization code.', {
        head: req.method === 'HEAD',
        cookies: [clearState],
        retryUrl: authUrl(base(), 'login'),
      })
      return
    }
    let tokens
    try {
      tokens = await oidc.exchangeCode({
        code,
        redirectUri: authUrl(base(), 'callback'),
        verifier: statePayload.vf,
      })
    } catch (error) {
      ctx.logger.warn(`dsh-oidc: token exchange failed: ${error instanceof Error ? error.message : String(error)}`)
      sendError(res, 502, 'The identity provider could not complete sign-in.', {
        head: req.method === 'HEAD',
        cookies: [clearState],
        retryUrl: authUrl(base(), 'login'),
      })
      return
    }
    let claims
    try {
      claims = await oidc.verifyIdToken(tokens.id_token, { nonce: statePayload.n })
    } catch (error) {
      ctx.logger.warn(`dsh-oidc: ID token rejected: ${error instanceof Error ? error.message : String(error)}`)
      sendError(res, 400, 'The sign-in response could not be verified.', {
        head: req.method === 'HEAD',
        cookies: [clearState],
        retryUrl: authUrl(base(), 'login'),
      })
      return
    }
    const access = roleAccess(claims, config)
    if (!access.allowed) {
      ctx.logger.warn(`dsh-oidc: access denied for sub ${String(claims.sub)}: ${access.reason}`)
      sendError(res, 403, 'This account is not allowed to access this Host.', {
        head: req.method === 'HEAD',
        cookies: [clearState],
        retryUrl: authUrl(base(), 'login'),
      })
      return
    }
    const now = Date.now()
    const sessionCookie = serializeCookie(SESSION_COOKIE, signPayload(secret, {
      sub: claims.sub,
      h: base().host,
      iat: now,
      exp: now + SESSION_TTL_MS,
    }), {
      maxAgeSeconds: SESSION_MAX_AGE_SECONDS,
      secure: secure(),
    })
    sendCompletion(res, appUrl(base(), statePayload.r), [clearState, sessionCookie], false)
  }

  function handleLogout(req, res) {
    if (req.method !== 'GET' && req.method !== 'POST') {
      sendError(res, 405, 'Method not allowed.', { head: req.method === 'HEAD' })
      return
    }
    if (!hostMatches(req.headers)) {
      sendError(res, 403, 'Request host is not the configured public host.', { head: req.method === 'HEAD' })
      return
    }
    if (headerValue(req.headers, 'sec-fetch-site') === 'cross-site') {
      sendError(res, 403, 'Cross-site sign-out is not allowed.', { head: req.method === 'HEAD' })
      return
    }
    const origin = headerValue(req.headers, 'origin')
    if (origin !== undefined && origin !== base().origin) {
      sendError(res, 403, 'Request origin is not the configured public origin.', { head: req.method === 'HEAD' })
      return
    }
    sendCompletion(res, appUrl(base(), '/'), [
      clearCookie(SESSION_COOKIE, { secure: secure() }),
      clearCookie(STATE_COOKIE, { secure: secure() }),
    ], req.method === 'HEAD')
  }

  ctx.connection.authentication.register({ authenticate })
  ctx.on('webserver/request', async (request, response, next) => {
    let url
    try {
      url = new URL(request.url ?? '/', 'http://dsh.invalid')
    } catch {
      await next()
      return
    }
    try {
      if (url.pathname === LOGIN_PATH) {
        await handleLogin(request, response)
        return
      }
      if (url.pathname === CALLBACK_PATH) {
        await handleCallback(request, response)
        return
      }
      if (url.pathname === LOGOUT_PATH) {
        handleLogout(request, response)
        return
      }
      if (!isIndexPath(url.pathname)) {
        await next()
        return
      }
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        await next()
        return
      }
      const admission = ctx.connection.authentication.authenticate({
        headers: request.headers,
        method: request.method,
        url: url.href,
        socket: request.socket,
      })
      if ('peer' in admission) {
        await next()
        return
      }
      if (!wantsHtml(request.headers)) {
        await next()
        return
      }
      const target = new URL('auth/login', base())
      target.searchParams.set('returnTo', url.pathname + url.search)
      sendRedirect(response, target.href)
    } catch (error) {
      ctx.logger.warn(`dsh-oidc: request failed: ${error instanceof Error ? error.message : String(error)}`)
      if (!response.headersSent) {
        sendError(response, 500, 'OIDC sign-in is unavailable.', {
          head: request.method === 'HEAD',
          retryUrl: authUrl(base(), 'login'),
        })
      } else {
        response.destroy()
      }
    }
  })

  ctx.logger.info(`dsh-oidc: enabled (issuer=${config.issuer}, roleClaim=${config.roleClaim || 'none'})`)
  if (config.roleClaim === '') {
    ctx.logger.info('dsh-oidc: no roleClaim configured; any identity-provider-authenticated user is admitted')
  }
}
