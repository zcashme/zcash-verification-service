/**
 * NextAuth / Auth.js v5 integration for ZcashMe.
 *
 * Uses the built-in OIDC provider type with automatic discovery.
 * PKCE is handled automatically.
 *
 * Setup:
 *   1. npm install next-auth
 *   2. Copy this config into your auth.ts
 *   3. Add the callback URL to the ZcashMe auth service client config
 *
 * Callback URL: https://your-app.com/api/auth/callback/zcashme
 */

import NextAuth from "next-auth";

export const { handlers, auth } = NextAuth({
  providers: [
    {
      id: "zcashme",
      name: "ZcashMe",
      type: "oidc",
      issuer: "https://auth.zcash.me",
      clientId: "pgpz",
      clientSecret: "",  // PKCE only — no secret

      authorization: {
        params: {
          scope: "openid profile",
          // Pass user_id to add a link to the user's ZcashMe profile.
          // Can be a verification code, handle, or any identifier.
          // Omit if you don't need it.
          user_id: "PGPZ-A3F2B1",
        },
      },

      // Map ZcashMe claims to your session user
      profile(profile) {
        return {
          id: profile.sub,
          name: profile.name,
          image: profile.picture,
          // Custom fields (add these to your User type):
          zcashAddress: profile.zcash_unified_address,
          zcashmeUsername: profile.preferred_username,
        };
      },
    },
  ],
});