/**
 * Better Auth Integration Guide for ZcashMe OIDC.
 *
 * This guide demonstrates how to integrate ZcashMe authentication using Better Auth's
 * `genericOAuth` plugin with OpenID Connect (OIDC) discovery.
 *
 * Key Notes:
 * - ZcashMe uses PKCE only — no client secret is required.
 * - Better Auth PR #9069 updated the OAuth API:
 *   • Use `signIn.social({ provider: "zcashme" })` on the client (replacing deprecated `signIn.oauth2`).
 *   • `genericOAuthClient()` is deprecated and no longer needed on the client.
 *   • Callback URL route format is `/api/auth/callback/:id` (replacing `/api/auth/oauth2/callback/:providerId`).
 *   • PKCE defaults to `true`.
 *
 * Setup Steps:
 *   1. Install Better Auth:
 *      npm install better-auth
 *   2. Configure server-side authentication in your `auth.ts` (see example below).
 *   3. Configure client-side authentication in `auth-client.ts` using `createAuthClient()`.
 *   4. Register your redirect callback URL with the ZcashMe auth service client configuration:
 *      https://your-app.com/api/auth/callback/zcashme
 *
 * Callback URL Format: https://your-app.com/api/auth/callback/zcashme
 */

import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";

// ── 1. Server Configuration (auth.ts) ─────────────────────

/**
 * Server-side Better Auth setup using genericOAuth plugin.
 */
export const auth = betterAuth({
  plugins: [
    genericOAuth({
      config: [
        {
          // Provider identifier — matches the provider name used on the client
          providerId: "zcashme",

          // Your registered ZcashMe OAuth Client ID
          clientId: process.env.ZCASHME_CLIENT_ID || "pgpz",

          // ZcashMe uses PKCE authentication — no client secret needed
          clientSecret: "",

          // OIDC Discovery URL for ZcashMe auth service
          discoveryUrl: "https://auth.zcash.me/.well-known/openid-configuration",

          // Standard OIDC scopes requested during authorization
          scopes: ["openid", "profile"],

          // Enable PKCE (Proof Key for Code Exchange) — required by ZcashMe (defaults to true in Better Auth v1.1+)
          pkce: true,

          // ZcashMe-specific custom authorization parameters:
          // The 'user_id' parameter adds a link to the user's ZcashMe profile
          // (can be a verification code, handle, or external account ID).
          authorizationUrlParams: {
            user_id: "PGPZ-A3F2B1",
          },

          // Map ZcashMe OIDC claims to your application's user model.
          //
          // ZcashMe OIDC Claims returned from auth.zcash.me:
          //   - sub: Zcash unified address (unique primary ID)
          //   - name: User's display name (from DB display_name field)
          //   - preferred_username: ZcashMe username (from DB name field)
          //   - picture: Profile image URL
          //   - zcash_unified_address: Zcash unified address (custom claim, identical to sub)
          mapProfileToUser: (profile) => ({
            id: profile.sub,
            name: profile.name,
            image: profile.picture,
            // Custom user model attributes:
            zcashAddress: profile.zcash_unified_address || profile.sub,
            zcashmeUsername: profile.preferred_username,
          }),
        },
      ],
    }),
  ],
});

// ── 2. Client Side Configuration (auth-client.ts) ─────────

/*
import { createAuthClient } from "better-auth/client";

// Note: genericOAuthClient() is DEPRECATED in Better Auth (PR #9069)
// and is no longer required in client plugins.
export const authClient = createAuthClient();
*/

// ── 3. Client Sign-In Example ──────────────────────────────

/*
import { authClient } from "./auth-client";

// Trigger ZcashMe OIDC sign-in flow
export async function signInWithZcashMe() {
  // Use the updated signIn.social API (replacing deprecated signIn.oauth2)
  await authClient.signIn.social({
    provider: "zcashme",       // Matches providerId defined in server config
    callbackURL: "/dashboard", // Page to redirect to after successful sign-in
  });
}
*/

// ── 4. Type Definitions for ZcashMe OIDC Claims ─────────────

export interface ZcashMeProfile {
  /** Zcash unified address (primary identifier) */
  sub: string;
  /** User display name (from DB display_name field) */
  name?: string;
  /** ZcashMe handle / username (from DB name field) */
  preferred_username?: string;
  /** Profile image URL */
  picture?: string;
  /** Zcash unified address (custom claim, same as sub) */
  zcash_unified_address: string;
}