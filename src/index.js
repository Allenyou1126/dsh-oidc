/** Host plugin entry: Config schema and apply export. */
import z from '@deepseek-ai/schemastery'
import { apply as applyPlugin } from './plugin.js'

/** Stable plugin name. */
export const name = 'dsh-oidc'

/** Services required before the OIDC middleware and provider can register. */
export const inject = ['connection', 'connection.authentication', 'webServer', 'webApp']

/** Minimal configuration; empty values fall back to DSH_OIDC_* environment variables. */
export const Config = z.object({
  enabled: z.boolean().default(true),
  issuer: z.string().default(''),
  clientId: z.string().default(''),
  scopes: z.array(String).default([]),
  roleClaim: z.string().default(''),
  allowedRoles: z.array(String).default([]),
})

/**
 * Register the OIDC authentication provider and its HTTP middleware.
 * @param ctx - plugin context.
 * @param config - validated plugin Config.
 */
export function apply(ctx, config) {
  applyPlugin(ctx, config)
}
