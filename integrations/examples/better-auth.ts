/**
 * Better Auth integration for ZcashMe.
 *
 * Uses Better Auth's genericOAuth plugin with OIDC discovery.
 * PKCE is enabled by default. No client secret needed.
 *
 * Setup:
 *   1. npm install better-auth
 *   2. Copy this config into your auth.ts
 *   3. Add the callback URL to the ZcashMe auth service client config
 *
 * Callback URL: https://your-app.com/api/auth/oauth2/callback/zcashme
 */

import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";

export const auth = betterAuth({
  plugins: [
    genericOAuth({
      config: [
        {
          providerId: "zcashme",
          clientId: "pgpz",
          clientSecret: "",  // PKCE only — no secret
          discoveryUrl: "https://auth.zcash.me/.well-known/openid-configuration",
          scopes: ["openid", "profile"],
          pkce: true,

          // Pass user_id to add a link to the user's ZcashMe profile.
          // Can be a verification code, handle, or any identifier.
          // Omit if you don't need it.
          authorizationUrlParams: {
            user_id: "PGPZ-A3F2B1",
          },

          // Map ZcashMe claims to your user model
          mapProfileToUser: (profile) => ({
            id: profile.sub,
            name: profile.name,
            image: profile.picture,
            // Custom fields:
            zcashAddress: profile.zcash_unified_address,
            zcashmeUsername: profile.preferred_username,
          }),
        },
      ],
    }),
  ],
});

// ── Client side ──────────────────────────────────────────

// auth-client.ts
// import { createAuthClient } from "better-auth/client";
// import { genericOAuthClient } from "better-auth/client/plugins";
//
// export const authClient = createAuthClient({
//   plugins: [genericOAuthClient()],
// });

// Sign in:
// await authClient.signIn.oauth2({
//   providerId: "zcashme",
//   callbackURL: "/dashboard",
// });