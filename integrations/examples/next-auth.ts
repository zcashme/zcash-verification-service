/**
 * NextAuth / Auth.js v5 integration for ZcashMe.
 *
 * Uses the built-in OIDC provider type with automatic discovery.
 * PKCE is enforced via `checks: ["pkce"]`. No client secret needed.
 *
 * Setup:
 *   1. npm install next-auth@beta
 *   2. Copy this config into your auth.ts
 *   3. Add the callback URL to the ZcashMe auth service client config
 *
 * Callback URL: /api/auth/callback/zcashme (e.g. https://your-app.com/api/auth/callback/zcashme)
 */

import NextAuth from "next-auth";

/**
 * ZcashMe OIDC Claims returned by auth.zcash.me
 */
export interface ZcashMeProfile {
  sub: string; // Zcash unified address
  name?: string; // Display name
  preferred_username?: string; // ZcashMe username
  picture?: string; // Profile image URL
  zcash_unified_address?: string; // Zcash unified address (same as sub)
}

export const { handlers, auth } = NextAuth({
  providers: [
    {
      id: "zcashme",
      name: "ZcashMe",
      type: "oidc",
      issuer: "https://auth.zcash.me",
      clientId: "pgpz",
      clientSecret: "", // PKCE only — no secret

      checks: ["pkce"],

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
      profile(profile: ZcashMeProfile) {
        return {
          id: profile.sub,
          name: profile.name,
          image: profile.picture,
          // Custom fields (add these to your User type):
          zcashAddress: profile.zcash_unified_address ?? profile.sub,
          zcashmeUsername: profile.preferred_username,
        };
      },
    },
  ],
});