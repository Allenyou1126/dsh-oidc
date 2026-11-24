/** Minimal RS256 ID-token decoding and verification. */
import { createPublicKey, verify as verifySignature } from 'node:crypto'

const MAX_TOKEN_BYTES = 32 * 1024
const BASE64URL = /^[A-Za-z0-9_-]+$/u
const CLOCK_SKEW_SECONDS = 60

/** Typed verification failure; `code` is safe to log. */
export class JwtError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'JwtError'
    this.code = code
  }
}

function decodePart(value, label) {
  if (typeof value !== 'string' || !BASE64URL.test(value)) throw new JwtError('malformed', `invalid ${label}`)
  let parsed
  try {
    parsed = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'))
  } catch {
    throw new JwtError('malformed', `invalid ${label}`)
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new JwtError('malformed', `invalid ${label}`)
  }
  return parsed
}

/**
 * Decode a compact JWT without verifying it.
 * @returns header, payload, signing input, and signature bytes.
 */
export function decodeJwt(token) {
  if (typeof token !== 'string' || token.length === 0) throw new JwtError('malformed', 'token is missing')
  if (Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) throw new JwtError('too-large', 'token is too large')
  const parts = token.split('.')
  if (parts.length !== 3) throw new JwtError('malformed', 'token must have three parts')
  const [encodedHeader, encodedPayload, encodedSignature] = parts
  const header = decodePart(encodedHeader, 'header')
  const payload = decodePart(encodedPayload, 'payload')
  if (typeof header.alg !== 'string') throw new JwtError('malformed', 'header has no algorithm')
  if (header.crit !== undefined) throw new JwtError('unsupported', 'critical headers are not supported')
  if (header.b64 === false) throw new JwtError('unsupported', 'unencoded payloads are not supported')
  if (header.kid !== undefined && typeof header.kid !== 'string') throw new JwtError('malformed', 'invalid key id')
  if (typeof encodedSignature !== 'string' || !BASE64URL.test(encodedSignature)) {
    throw new JwtError('malformed', 'invalid signature')
  }
  return {
    header,
    payload,
    signingInput: `${encodedHeader}.${encodedPayload}`,
    signature: Buffer.from(encodedSignature, 'base64url'),
  }
}

function selectKeys(keys, header) {
  if (!Array.isArray(keys)) return []
  return keys.filter((key) => {
    if (key === null || typeof key !== 'object') return false
    if (key.kty !== 'RSA') return false
    if (key.use !== undefined && key.use !== 'sig') return false
    if (key.alg !== undefined && key.alg !== 'RS256') return false
    if (header.kid !== undefined && key.kid !== header.kid) return false
    return true
  })
}

function verifyWithKey(parts, jwk) {
  try {
    const key = createPublicKey({ key: jwk, format: 'jwk' })
    return verifySignature('RSA-SHA256', Buffer.from(parts.signingInput, 'utf8'), key, parts.signature)
  } catch {
    return false
  }
}

function stripTrailingSlash(value) {
  return value.replace(/\/+$/u, '')
}

function validateClaims(payload, {
  issuer,
  audience,
  nonce,
  now,
  skewSeconds = CLOCK_SKEW_SECONDS,
}) {
  if (typeof payload.iss !== 'string' || stripTrailingSlash(payload.iss) !== stripTrailingSlash(issuer)) {
    throw new JwtError('issuer', 'unexpected issuer')
  }
  const audiences = Array.isArray(payload.aud)
    ? payload.aud.filter(value => typeof value === 'string')
    : typeof payload.aud === 'string' ? [payload.aud] : []
  if (!audiences.includes(audience)) throw new JwtError('audience', 'unexpected audience')
  if (payload.azp !== undefined && payload.azp !== audience) throw new JwtError('authorized-party', 'unexpected azp')
  if (audiences.length > 1 && payload.azp !== audience) throw new JwtError('authorized-party', 'azp is required for multiple audiences')
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) throw new JwtError('expiry', 'token has no expiry')
  const skewMs = skewSeconds * 1000
  if (payload.exp * 1000 <= now - skewMs) throw new JwtError('expired', 'token has expired')
  if (payload.iat !== undefined) {
    if (typeof payload.iat !== 'number' || !Number.isFinite(payload.iat)) throw new JwtError('issued-at', 'invalid iat')
    if (payload.iat * 1000 > now + skewMs) throw new JwtError('issued-at', 'token was issued in the future')
  }
  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== 'number' || !Number.isFinite(payload.nbf)) throw new JwtError('not-before', 'invalid nbf')
    if (payload.nbf * 1000 > now + skewMs) throw new JwtError('not-before', 'token is not valid yet')
  }
  if (nonce !== undefined && payload.nonce !== nonce) throw new JwtError('nonce', 'unexpected nonce')
  if (typeof payload.sub !== 'string' || payload.sub === '') throw new JwtError('subject', 'token has no subject')
}

/**
 * Verify an RS256 ID token against a JWKS key set and its expected claims.
 * @param token - compact JWT.
 * @param options - JWKS keys plus expected issuer, audience, nonce, and time.
 * @returns verified claims.
 */
export function verifyJwt(token, {
  keys,
  issuer,
  audience,
  nonce,
  now = Date.now(),
  skewSeconds = CLOCK_SKEW_SECONDS,
}) {
  const parts = decodeJwt(token)
  if (parts.header.alg !== 'RS256') throw new JwtError('unsupported-alg', `unsupported algorithm ${parts.header.alg}`)
  const candidates = selectKeys(keys, parts.header)
  if (candidates.length === 0) throw new JwtError('unknown-key', 'no matching JWKS key')
  if (!candidates.some(jwk => verifyWithKey(parts, jwk))) throw new JwtError('signature', 'invalid token signature')
  validateClaims(parts.payload, { issuer, audience, nonce, now, skewSeconds })
  return parts.payload
}
