import assert from 'node:assert/strict'
import test from 'node:test'
import { isLoopbackHostname, normalizeIssuer, resolveConfig } from '../src/config.js'

test('inactive without issuer or client id', () => {
  const missingIssuer = resolveConfig({}, {})
  assert.equal(missingIssuer.active, false)
  assert.match(missingIssuer.reason, /missing DSH_OIDC_ISSUER/u)

  const missingClient = resolveConfig({ issuer: 'https://auth.example.com' }, {})
  assert.equal(missingClient.active, false)
  assert.match(missingClient.reason, /missing DSH_OIDC_CLIENT_ID/u)
})

test('environment provides the minimal configuration', () => {
  const config = resolveConfig({}, {
    DSH_OIDC_ISSUER: 'https://auth.example.com/',
    DSH_OIDC_CLIENT_ID: 'dsh-client',
    DSH_OIDC_SCOPES: 'openid profile',
    DSH_OIDC_ROLE_CLAIM: 'roles',
    DSH_OIDC_ALLOWED_ROLES: 'dsh-owner, dsh-admin',
  })
  assert.equal(config.active, true)
  assert.equal(config.issuer, 'https://auth.example.com')
  assert.equal(config.clientId, 'dsh-client')
  assert.deepEqual(config.scopes, ['openid', 'profile'])
  assert.equal(config.roleClaim, 'roles')
  assert.deepEqual(config.allowedRoles, ['dsh-owner', 'dsh-admin'])
})

test('openid is always added and duplicate scopes are removed', () => {
  const config = resolveConfig({
    issuer: 'https://auth.example.com',
    clientId: 'client',
    scopes: ['profile', 'profile', 'openid'],
  }, {})
  assert.deepEqual(config.scopes, ['openid', 'profile'])
})

test('disabled by Config or environment', () => {
  const byConfig = resolveConfig({
    enabled: false,
    issuer: 'https://auth.example.com',
    clientId: 'client',
  }, {})
  assert.equal(byConfig.active, false)
  assert.match(byConfig.reason, /disabled/u)

  const byEnv = resolveConfig({
    issuer: 'https://auth.example.com',
    clientId: 'client',
  }, { DSH_OIDC_ENABLED: '0' })
  assert.equal(byEnv.active, false)
  assert.match(byEnv.reason, /disabled/u)
})

test('HTTP issuers are allowed only on loopback', () => {
  const local = resolveConfig({ issuer: 'http://127.0.0.1:8080', clientId: 'client' }, {})
  assert.equal(local.active, true)

  const remote = resolveConfig({ issuer: 'http://auth.example.com', clientId: 'client' }, {})
  assert.equal(remote.active, false)
  assert.match(remote.reason, /invalid issuer/u)
})

test('issuer normalization strips trailing slashes and credentials are rejected', () => {
  assert.equal(normalizeIssuer('https://auth.example.com/').href, 'https://auth.example.com/')
  assert.equal(normalizeIssuer('https://auth.example.com/realms/acme/').href, 'https://auth.example.com/realms/acme')
  assert.throws(() => normalizeIssuer('https://user:pass@auth.example.com'), /credentials/u)
  assert.throws(() => normalizeIssuer('https://auth.example.com/?x=1'), /query or fragment/u)
})

test('loopback hostname classification', () => {
  assert.equal(isLoopbackHostname('127.0.0.1'), true)
  assert.equal(isLoopbackHostname('127.42.0.9'), true)
  assert.equal(isLoopbackHostname('[::1]'), true)
  assert.equal(isLoopbackHostname('localhost'), true)
  assert.equal(isLoopbackHostname('auth.example.com'), false)
  assert.equal(isLoopbackHostname('10.0.0.1'), false)
})

test('role claim is optional and allowed roles are exact values', () => {
  const noGuard = resolveConfig({ issuer: 'https://auth.example.com', clientId: 'client' }, {})
  assert.equal(noGuard.roleClaim, '')
  assert.deepEqual(noGuard.allowedRoles, [])

  const guard = resolveConfig({
    issuer: 'https://auth.example.com',
    clientId: 'client',
    roleClaim: 'urn:zitadel:iam:org:project:roles',
    allowedRoles: ['dsh-owner'],
  }, {})
  assert.equal(guard.roleClaim, 'urn:zitadel:iam:org:project:roles')
  assert.deepEqual(guard.allowedRoles, ['dsh-owner'])
})
