/** Resolve the plugin's small configuration surface from Config and DSH_OIDC_* env. */
import { isIP } from 'node:net'

const ENV = {
  enabled: 'DSH_OIDC_ENABLED',
  issuer: 'DSH_OIDC_ISSUER',
  clientId: 'DSH_OIDC_CLIENT_ID',
  scopes: 'DSH_OIDC_SCOPES',
  roleClaim: 'DSH_OIDC_ROLE_CLAIM',
  allowedRoles: 'DSH_OIDC_ALLOWED_ROLES',
}

function text(value) {
  return typeof value === 'string' ? value.trim() : ''
}

function configOrEnv(value, envValue) {
  const direct = text(value)
  return direct === '' ? text(envValue) : direct
}

/** Whether a hostname names the local machine (loopback only). */
export function isLoopbackHostname(hostname) {
  const host = String(hostname).replace(/^\[|\]$/gu, '').toLowerCase()
  if (host === 'localhost') return true
  const family = isIP(host)
  if (family === 4) return host.startsWith('127.')
  if (family === 6) return host === '::1' || host === '0:0:0:0:0:0:0:1'
  return false
}

/**
 * Validate an issuer and strip its trailing slash for comparisons.
 * HTTP is accepted only for loopback development issuers.
 * @param value - configured issuer.
 * @returns normalized issuer URL.
 */
export function normalizeIssuer(value) {
  let url
  try {
    url = new URL(value)
  } catch {
    throw new Error('issuer must be an absolute URL')
  }
  if (url.username !== '' || url.password !== '') throw new Error('issuer must not contain credentials')
  if (url.search !== '' || url.hash !== '') throw new Error('issuer must not contain a query or fragment')
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopbackHostname(url.hostname))) {
    throw new Error('issuer must use HTTPS (HTTP is allowed only for loopback development)')
  }
  const path = url.pathname.replace(/\/+$/u, '')
  return new URL(`${url.origin}${path}`)
}

function resolveScopes(rawScopes, envValue) {
  const source = Array.isArray(rawScopes) && rawScopes.length > 0
    ? rawScopes
    : String(envValue ?? '').split(/[\s,]+/u)
  const scopes = []
  for (const value of source) {
    if (typeof value !== 'string') continue
    const scope = value.trim()
    if (scope !== '' && !scopes.includes(scope)) scopes.push(scope)
  }
  if (scopes.includes('openid')) scopes.splice(scopes.indexOf('openid'), 1)
  scopes.unshift('openid')
  return scopes
}

function resolveList(rawValue, envValue, { commaOnly = false } = {}) {
  const source = Array.isArray(rawValue) && rawValue.length > 0
    ? rawValue
    : String(envValue ?? '').split(commaOnly ? ',' : /[\s,]+/u)
  const values = []
  for (const value of source) {
    if (typeof value !== 'string') continue
    const entry = value.trim()
    if (entry !== '' && !values.includes(entry)) values.push(entry)
  }
  return values
}

/**
 * Resolve and validate configuration without throwing.
 * Inactive results carry a human-readable `reason` for the activation log.
 * @param raw - Schemastery-validated Config values.
 * @param env - environment source (injectable for tests).
 * @returns resolved configuration, active or inactive.
 */
export function resolveConfig(raw = {}, env = process.env) {
  const enabled = raw.enabled !== false && env[ENV.enabled] !== '0'
  const issuerValue = configOrEnv(raw.issuer, env[ENV.issuer])
  const clientId = configOrEnv(raw.clientId, env[ENV.clientId])
  const scopes = resolveScopes(raw.scopes, env[ENV.scopes])
  const roleClaim = configOrEnv(raw.roleClaim, env[ENV.roleClaim])
  const allowedRoles = resolveList(raw.allowedRoles, env[ENV.allowedRoles], { commaOnly: true })
  const base = { enabled, issuer: issuerValue, clientId, scopes, roleClaim, allowedRoles }

  if (!enabled) return { ...base, active: false, reason: 'disabled by DSH_OIDC_ENABLED or Config.enabled' }
  if (issuerValue === '') return { ...base, active: false, reason: 'missing DSH_OIDC_ISSUER' }
  if (clientId === '') return { ...base, active: false, reason: 'missing DSH_OIDC_CLIENT_ID' }

  let issuerUrl
  try {
    issuerUrl = normalizeIssuer(issuerValue)
  } catch (error) {
    return {
      ...base,
      active: false,
      reason: `invalid issuer: ${error instanceof Error ? error.message : String(error)}`,
    }
  }

  return {
    ...base,
    active: true,
    issuer: issuerUrl.href.replace(/\/$/u, ''),
    issuerUrl,
  }
}

export { ENV }
