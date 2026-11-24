/** Minimal signed-cookie helpers for the state and browser-session credentials. */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

const VERSION = 'v1'
const MAX_VALUE_BYTES = 4096
const MAX_CLOCK_SKEW_MS = 60_000
const BASE64URL = /^[A-Za-z0-9_-]+$/u

/** Create a cookie-safe random token. */
export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString('base64url')
}

function decodeBase64Url(value) {
  if (typeof value !== 'string' || value.length === 0 || !BASE64URL.test(value)) return undefined
  const decoded = Buffer.from(value, 'base64url')
  return decoded.toString('base64url') === value ? decoded : undefined
}

function signature(secret, body) {
  return createHmac('sha256', secret).update(body).digest()
}

/**
 * Sign a JSON payload as `v1.<base64url(body)>.<base64url(hmac)>`.
 * @param secret - HMAC key.
 * @param payload - JSON value; `v: 1` is added.
 */
export function signPayload(secret, payload) {
  const body = Buffer.from(JSON.stringify({ v: 1, ...payload }), 'utf8').toString('base64url')
  return `${VERSION}.${body}.${signature(secret, body).toString('base64url')}`
}

/**
 * Verify a signed cookie value and its host/expiry constraints.
 * @param secret - HMAC key.
 * @param value - cookie value, or undefined.
 * @param options - maximum age, current time, and bound host.
 * @returns payload, or undefined for any malformed/tampered/expired value.
 */
export function verifyPayload(secret, value, { maxAgeMs, now = Date.now(), host } = {}) {
  if (typeof value !== 'string' || value.length > MAX_VALUE_BYTES) return undefined
  const parts = value.split('.')
  if (parts.length !== 3) return undefined
  const [version, body, encodedSignature] = parts
  if (version !== VERSION || body === undefined || encodedSignature === undefined) return undefined
  const actual = decodeBase64Url(encodedSignature)
  if (actual === undefined) return undefined
  const expected = signature(secret, body)
  if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) return undefined
  const bodyBytes = decodeBase64Url(body)
  if (bodyBytes === undefined) return undefined
  let payload
  try {
    payload = JSON.parse(bodyBytes.toString('utf8'))
  } catch {
    return undefined
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return undefined
  if (payload.v !== 1 || typeof payload.h !== 'string') return undefined
  if (!Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)) return undefined
  if (Number.isSafeInteger(maxAgeMs) && payload.exp - payload.iat > maxAgeMs + MAX_CLOCK_SKEW_MS) return undefined
  if (payload.exp <= now) return undefined
  if (payload.iat > now + MAX_CLOCK_SKEW_MS) return undefined
  if (host !== undefined && payload.h !== host) return undefined
  return payload
}

/** Read one cookie value from a Cookie request header. */
export function readCookie(headerValue, name) {
  if (typeof headerValue !== 'string') return undefined
  for (const segment of headerValue.split(';')) {
    const at = segment.indexOf('=')
    if (at === -1) continue
    if (segment.slice(0, at).trim() === name) return segment.slice(at + 1).trim()
  }
  return undefined
}

/** Serialize one Set-Cookie header value. */
export function serializeCookie(name, value, {
  maxAgeSeconds,
  secure = false,
  sameSite = 'Lax',
  path = '/',
  now = Date.now(),
} = {}) {
  const maxAge = Math.max(0, Math.floor(maxAgeSeconds ?? 0))
  const attributes = [
    `${name}=${value}`,
    `Max-Age=${maxAge}`,
    `Expires=${new Date(now + maxAge * 1000).toUTCString()}`,
    `Path=${path}`,
    'HttpOnly',
    `SameSite=${sameSite}`,
  ]
  if (secure) attributes.push('Secure')
  return attributes.join('; ')
}

/** Serialize a Set-Cookie value that removes the cookie. */
export function clearCookie(name, { secure = false, path = '/' } = {}) {
  const attributes = [
    `${name}=`,
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    `Path=${path}`,
    'HttpOnly',
    'SameSite=Lax',
  ]
  if (secure) attributes.push('Secure')
  return attributes.join('; ')
}
