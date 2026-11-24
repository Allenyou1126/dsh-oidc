/** Small OIDC public-client implementation: discovery, code exchange, JWKS, RS256 ID tokens. */
import { isLoopbackHostname } from './config.js'
import { verifyJwt, JwtError } from './jwt.js'

const MAX_RESPONSE_BYTES = 256 * 1024
const MAX_JWKS_KEYS = 32

/** Typed OIDC failure with a safe diagnostic code. */
export class OidcError extends Error {
  constructor(code, message, { status, idpCode } = {}) {
    super(message)
    this.name = 'OidcError'
    this.code = code
    this.status = status
    this.idpCode = idpCode
  }
}

function endpointUrl(value, label) {
  let url
  try {
    url = new URL(value)
  } catch {
    throw new OidcError('discovery', `${label} is not an absolute URL`)
  }
  if (url.username !== '' || url.password !== '') throw new OidcError('discovery', `${label} contains credentials`)
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopbackHostname(url.hostname))) {
    throw new OidcError('discovery', `${label} must use HTTPS`)
  }
  return url
}

function stripTrailingSlash(value) {
  return value.replace(/\/+$/u, '')
}

/** OIDC client bound to one issuer and public client id (no client secret). */
export class OidcClient {
  constructor({ issuer, clientId, scopes, fetchImpl = globalThis.fetch, timeoutMs = 10_000 }) {
    this.issuer = stripTrailingSlash(issuer)
    this.clientId = clientId
    this.scopes = scopes
    this.fetch = fetchImpl
    this.timeoutMs = timeoutMs
    this.discoveryCache = undefined
    this.jwksCache = undefined
  }

  /** Fetch and validate the discovery document once per activation. */
  async discovery() {
    if (this.discoveryCache !== undefined) return this.discoveryCache
    const discoveryUrl = new URL('.well-known/openid-configuration', `${this.issuer}/`)
    const document = await this.requestJson(discoveryUrl, {
      headers: { accept: 'application/json' },
      label: 'discovery',
    })
    if (typeof document.issuer !== 'string' || stripTrailingSlash(document.issuer) !== this.issuer) {
      throw new OidcError('discovery', 'discovery issuer does not match DSH_OIDC_ISSUER')
    }
    if (typeof document.authorization_endpoint !== 'string'
      || typeof document.token_endpoint !== 'string'
      || typeof document.jwks_uri !== 'string') {
      throw new OidcError('discovery', 'discovery document is missing required endpoints')
    }
    endpointUrl(document.authorization_endpoint, 'authorization_endpoint')
    endpointUrl(document.token_endpoint, 'token_endpoint')
    endpointUrl(document.jwks_uri, 'jwks_uri')
    if (Array.isArray(document.code_challenge_methods_supported)
      && !document.code_challenge_methods_supported.includes('S256')) {
      throw new OidcError('discovery', 'identity provider does not support PKCE S256')
    }
    if (Array.isArray(document.response_types_supported) && !document.response_types_supported.includes('code')) {
      throw new OidcError('discovery', 'identity provider does not support the authorization code flow')
    }
    if (Array.isArray(document.id_token_signing_alg_values_supported)
      && !document.id_token_signing_alg_values_supported.includes('RS256')) {
      throw new OidcError('discovery', 'identity provider does not sign ID tokens with RS256')
    }
    this.discoveryCache = document
    return document
  }

  /** Fetch and cache the JWKS key set. */
  async jwks(force = false) {
    if (this.jwksCache !== undefined && !force) return this.jwksCache
    const document = await this.discovery()
    const value = await this.requestJson(endpointUrl(document.jwks_uri, 'jwks_uri'), {
      headers: { accept: 'application/json' },
      label: 'jwks',
    })
    if (!Array.isArray(value.keys) || value.keys.length === 0) throw new OidcError('jwks', 'JWKS has no keys')
    if (value.keys.length > MAX_JWKS_KEYS) throw new OidcError('jwks', 'JWKS has too many keys')
    this.jwksCache = { keys: value.keys }
    return this.jwksCache
  }

  /**
   * Exchange an authorization code as a public client (no client authentication).
   * @param options - code, the exact redirect_uri, and the PKCE verifier.
   * @returns token endpoint response with a non-empty id_token.
   */
  async exchangeCode({ code, redirectUri, verifier }) {
    const document = await this.discovery()
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: this.clientId,
      code_verifier: verifier,
    })
    const tokens = await this.requestJson(endpointUrl(document.token_endpoint, 'token_endpoint'), {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
      label: 'token',
    })
    if (typeof tokens.id_token !== 'string' || tokens.id_token === '') {
      throw new OidcError('token', 'token response has no id_token')
    }
    return tokens
  }

  /** Verify an ID token; refresh JWKS once when its signing key is unknown. */
  async verifyIdToken(idToken, { nonce }) {
    let keySet = await this.jwks()
    const verify = () => verifyJwt(idToken, {
      keys: keySet.keys,
      issuer: this.issuer,
      audience: this.clientId,
      nonce,
    })
    try {
      return verify()
    } catch (error) {
      if (!(error instanceof JwtError) || error.code !== 'unknown-key') throw error
      keySet = await this.jwks(true)
      return verify()
    }
  }

  async requestJson(url, { method = 'GET', headers, body, label }) {
    let response
    try {
      response = await this.fetch(url, {
        method,
        headers,
        body,
        redirect: 'follow',
        signal: AbortSignal.timeout(this.timeoutMs),
      })
    } catch (error) {
      throw new OidcError(label, `${label} request failed: ${error instanceof Error ? error.message : String(error)}`)
    }
    const text = await response.text()
    if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) throw new OidcError(label, `${label} response is too large`)
    if (!response.ok) {
      let idpCode
      try {
        const parsed = JSON.parse(text)
        if (parsed !== null && typeof parsed === 'object' && typeof parsed.error === 'string') idpCode = parsed.error
      } catch {
        // The diagnostic keeps only the status and the provider's error code.
      }
      throw new OidcError(label, `${label} endpoint returned HTTP ${String(response.status)}${idpCode ? ` (${idpCode})` : ''}`, {
        status: response.status,
        idpCode,
      })
    }
    let parsed
    try {
      parsed = JSON.parse(text)
    } catch {
      throw new OidcError(label, `${label} response is not JSON`)
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new OidcError(label, `${label} response is not a JSON object`)
    }
    return parsed
  }
}
