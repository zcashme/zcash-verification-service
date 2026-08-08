/**
 * Clerk integration for ZcashMe.
 *
 * Clerk uses a dashboard UI for custom OIDC providers — no code config.
 * This file documents the setup steps and includes a proxy for user_id.
 *
 * Setup (Dashboard):
 *   1. SSO Connections → Add connection → Custom provider
 *   2. Name: ZcashMe, Key: zcashme
 *   3. Discovery Endpoint: https://auth.zcash.me/.well-known/openid-configuration
 *   4. Client ID: pgpz, Client Secret: (leave empty)
 *   5. Enable PKCE: ✅
 *   6. Copy the Authorized redirect URL → add to ZcashMe auth service
 *   7. Enable connection
 *
 * Attribute Mapping (Dashboard):
 *   User ID        → sub
 *   First name      → name
 *   Profile image   → picture
 *
 * user_id: Clerk doesn't support custom auth params. Use a proxy:
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
  const params = new URLSearchParams(c.req.url.split("?")[1] || "");
  params.forEach((value, key) => url.searchParams.set(key, value));

  // Add user_id — generate or look up your app's identifier
  url.searchParams.set("user_id", "PGPZ-A3F2B1");

  return c.redirect(url.toString());
});

export default app;