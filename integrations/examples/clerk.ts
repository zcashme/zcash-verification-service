/**
 * Clerk integration for ZcashMe.
 *
 * Clerk uses a dashboard UI for custom OIDC providers — no code configuration required.
 * This file documents the setup steps and includes a proxy for forwarding custom `user_id` params.
 *
 * Setup (Dashboard):
 *   1. SSO Connections → Add connection → For all users → Custom provider
 *   2. Name: ZcashMe, Key: zcashme
 *   3. Discovery Endpoint: https://auth.zcash.me/.well-known/openid-configuration
 *   4. Client ID: your-client-id (e.g. 'pgpz')
 *   5. Enable PKCE toggle: ✅
 *   6. Client Secret: leave empty (PKCE only)
 *   7. Copy the Authorized redirect URL → submit it as a redirect URI in the ZcashMe auth service
 *
 * Attribute Mapping (Dashboard):
 *   - Standard OIDC claims (sub, name, preferred_username, picture) are auto-mapped.
 *   - Custom claim zcash_unified_address needs manual mapping.
 *
 * user_id Parameter:
 *   Clerk doesn't support custom authorization parameters natively.
 *   If your app needs user_id, use a proxy (see below).
 */

// ── Proxy for user_id (Cloudflare Worker / Hono) ─────────
//
// Deploy this as a small proxy that intercepts the authorization
// request and adds user_id before forwarding to ZcashMe.

import { Hono } from "hono";

const app = new Hono();

// Clerk sends the user to this proxy URL instead of ZcashMe directly.
// Set this proxy URL as the "Authorization URL" in Clerk's manual config.
app.get("/auth", (c) => {
  const url = new URL("https://auth.zcash.me/auth");

  // Copy all params Clerk sends
  const requestUrl = new URL(c.req.url);
  requestUrl.searchParams.forEach((value, key) => url.searchParams.set(key, value));

  // Add user_id — generate or look up your app's identifier
  url.searchParams.set("user_id", "PGPZ-A3F2B1");

  return c.redirect(url.toString());
});

export default app;