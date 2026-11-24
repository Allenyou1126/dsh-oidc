import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import test from 'node:test'
import { JwtError, verifyJwt } from '../src/jwt.js'

const now = 1_700_000_000_000
const nowSeconds = Math.floor(now / 1000)
const issuer = 'https://auth.example.com'
const audience = 'dsh-client'
const nonce = 'nonce-value'

function keyPair(kid) {
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048 })
  return {
    privateKey: pair.privateKey,
    jwk: { ...pair.publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' },
  }
}

const primary = keyPair('k1')
const secondary = keyPair('k2')

function token(claims = {}, { privateKey = primary.privateKey, kid = 'k1', alg = 'RS256' } = {}) {
  const header = Buffer.from(JSON.stringify({ alg, typ: 'JWT', kid })).toString('base64url')
  const payload = Buffer.from(JSON.stringify({
    iss: issuer,
    aud: audience,
    sub: 'user-1',
    iat: nowSeconds,
    exp: nowSeconds + 300,
    nonce,
    ...claims,
  })).toString('base64url')
  const input = `${header}.${payload}`
  const signature = alg === 'none' ? 'AA' : sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')
  return `${input}.${signature}`
}

function verify(value, overrides = {}) {
  return verifyJwt(value, {
    keys: [primary.jwk],
    issuer,
    audience,
    nonce,
    now,
    ...overrides,
  })
}

test('accepts a correctly signed RS256 token', () => {
  const claims = verify(token())
  assert.equal(claims.sub, 'user-1')
  assert.equal(claims.iss, issuer)
})

test('accepts a trailing slash difference in issuer', () => {
  const claims = verify(token({ iss: `${issuer}/` }))
  assert.equal(claims.iss, `${issuer}/`)
})

test('rejects a tampered signature', () => {
  const value = token()
  const parts = value.split('.')
  const signature = parts[2].startsWith('A') ? `B${parts[2].slice(1)}` : `A${parts[2].slice(1)}`
  assert.throws(() => verify(`${parts[0]}.${parts[1]}.${signature}`), error => error instanceof JwtError && error.code === 'signature')
})

test('rejects an unknown signing key', () => {
  assert.throws(() => verify(token({}, { privateKey: secondary.privateKey, kid: 'k2' })), error => error instanceof JwtError && error.code === 'unknown-key')
})

test('rejects the none algorithm', () => {
  assert.throws(() => verify(token({}, { alg: 'none' })), error => error instanceof JwtError && error.code === 'unsupported-alg')
})

test('rejects expired and not-yet-valid tokens', () => {
  assert.throws(() => verify(token({ exp: nowSeconds - 120 })), error => error instanceof JwtError && error.code === 'expired')
  assert.throws(() => verify(token({ nbf: nowSeconds + 300 })), error => error instanceof JwtError && error.code === 'not-before')
})

test('rejects wrong audience, issuer, and nonce', () => {
  assert.throws(() => verify(token({ aud: 'someone-else' })), error => error instanceof JwtError && error.code === 'audience')
  assert.throws(() => verify(token({ iss: 'https://other.example.com' })), error => error instanceof JwtError && error.code === 'issuer')
  assert.throws(() => verify(token({ nonce: 'wrong' })), error => error instanceof JwtError && error.code === 'nonce')
})

test('requires azp when the audience array has several values', () => {
  assert.throws(
    () => verify(token({ aud: [audience, 'other-client'] })),
    error => error instanceof JwtError && error.code === 'authorized-party',
  )
  const claims = verify(token({ aud: [audience, 'other-client'], azp: audience }))
  assert.equal(claims.azp, audience)
})
