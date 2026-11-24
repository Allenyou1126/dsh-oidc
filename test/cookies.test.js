import assert from 'node:assert/strict'
import test from 'node:test'
import {
  clearCookie,
  readCookie,
  serializeCookie,
  signPayload,
  verifyPayload,
} from '../src/cookies.js'

const secret = 'test-cookie-key-0123456789abcdef'
const now = 1_700_000_000_000

function payload(overrides = {}) {
  return {
    sub: 'user-1',
    h: 'dsh.example.com',
    iat: now,
    exp: now + 60_000,
    ...overrides,
  }
}

test('signed payload round-trips', () => {
  const value = signPayload(secret, payload())
  const verified = verifyPayload(secret, value, { maxAgeMs: 60_000, now, host: 'dsh.example.com' })
  assert.equal(verified.sub, 'user-1')
  assert.equal(verified.h, 'dsh.example.com')
})

test('tampered or malformed values are rejected', () => {
  const value = signPayload(secret, payload())
  const parts = value.split('.')
  const tampered = `${parts[0]}.${parts[1]}.${parts[2].startsWith('A') ? 'B' : 'A'}${parts[2].slice(1)}`
  assert.equal(verifyPayload(secret, tampered, { maxAgeMs: 60_000, now }), undefined)
  assert.equal(verifyPayload(secret, 'not-a-cookie', { maxAgeMs: 60_000, now }), undefined)
  assert.equal(verifyPayload('another-secret', value, { maxAgeMs: 60_000, now }), undefined)
})

test('expired and over-age payloads are rejected', () => {
  const expired = signPayload(secret, payload({ iat: now - 120_000, exp: now - 1 }))
  assert.equal(verifyPayload(secret, expired, { maxAgeMs: 60_000, now }), undefined)

  const longLived = signPayload(secret, payload({ iat: now, exp: now + 3_600_000 }))
  assert.equal(verifyPayload(secret, longLived, { maxAgeMs: 60_000, now }), undefined)
  assert.ok(verifyPayload(secret, longLived, { maxAgeMs: 3_600_000, now }))
})

test('host binding is enforced', () => {
  const value = signPayload(secret, payload())
  assert.equal(verifyPayload(secret, value, { maxAgeMs: 60_000, now, host: 'other.example.com' }), undefined)
})

test('cookie header parsing uses the first matching pair', () => {
  assert.equal(readCookie('a=1; dsh-oidc-state=abc; dsh-oidc-state=def', 'dsh-oidc-state'), 'abc')
  assert.equal(readCookie(undefined, 'x'), undefined)
  assert.equal(readCookie('a=1', 'x'), undefined)
})

test('serialized cookies carry the required attributes', () => {
  const value = serializeCookie('dsh-oidc-session', 'value', {
    maxAgeSeconds: 43200,
    secure: true,
    now,
  })
  assert.match(value, /^dsh-oidc-session=value;/u)
  assert.match(value, /Max-Age=43200/u)
  assert.match(value, /Path=\//u)
  assert.match(value, /HttpOnly/u)
  assert.match(value, /SameSite=Lax/u)
  assert.match(value, /Secure/u)

  const cleared = clearCookie('dsh-oidc-session', { secure: true })
  assert.match(cleared, /Max-Age=0/u)
  assert.match(cleared, /Expires=Thu, 01 Jan 1970/u)
  assert.match(cleared, /Secure/u)
})
