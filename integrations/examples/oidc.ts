/**
 * Raw OIDC integration for ZcashMe using oauth4webapi.
 *
 * For apps with custom auth — no Better Auth, NextAuth, or Clerk.
 * Just a server runtime (Node.js, Bun, Deno, Edge).
 *
 * Setup:
 *   1. npm install oauth4webapi
 *   2. Copy these functions into your server code
 *   3. Add the callback URL to the ZcashMe auth service client config
 *
 * Callback URL: https://your-app.com/callback (your choice)
 */

import * as oauth from "oauth4webapi";

const ISSUER = new URL("https://auth.zcash.me");
const CLIENT_ID = "pgpz";

// ── 1. Start: build authorization URL + PKCE ──────────────
//
// Call this when the user clicks "Sign in with ZcashMe".
// Store the codeVerifier and state in a cookie/session.
// Redirect the browser to the returned URL.

export async function createZcashMeAuthUrl(redirectUri: string, userId?: string) {
  // Discover the provider (cache this in production)
  const metadata = await oauth.discoveryRequest(ISSUER);
  const config = await oauth.processDiscoveryResponse(ISSUER, metadata);

  // Generate PKCE
  const codeVerifier = oauth.generateRandomCodeVerifier();
  const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);

  // Generate state (CSRF protection)
  const state = oauth.generateRandomState();

  // Build authorization URL
  const authUrl = new URL(config.authorization_endpoint!);
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", "openid profile");
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("state", state);

  // Optional: pass user_id to add a link to the user's ZcashMe profile
  if (userId) {
    authUrl.searchParams.set("user_id", userId);
  }

  return { url: authUrl.toString(), codeVerifier, state };
}

// ── 2. Callback: exchange code for tokens + user info ─────
//
// Call this when ZcashMe redirects back with ?code=...&state=...
// Validate state against what you stored in step 1.

export async function handleZcashMeCallback(params: {
  code: string;
  state: string;
  codeVerifier: string;
  expectedState: string;
  redirectUri: string;
}) {
  // Validate state (CSRF)
  if (params.state !== params.expectedState) {
    throw new Error("State mismatch — possible CSRF attack");
  }

  // Discover the provider (cache this in production)
  const metadata = await oauth.discoveryRequest(ISSUER);
  const config = await oauth.processDiscoveryResponse(ISSUER, metadata);

  const client: oauth.Client = { client_id: CLIENT_ID };

  // Exchange code for tokens
  const tokenResponse = await oauth.authorizationCodeGrantRequest(
    config,
    client,
    params.codeVerifier,
    params.code,
    new URL(params.redirectUri),
  );

  const tokens = await oauth.processAuthorizationCodeOAuthResponse(
    config,
    client,
    params.codeVerifier,
    tokenResponse,
  );

  // Fetch user info
  const userInfoResponse = await oauth.userInfoRequest(
    config,
    client,
    tokens.access_token!,
  );
  const user = await oauth.processUserInfoResponse(
    config,
    client,
    tokens.access_token!,
    userInfoResponse,
  );

  return {
    user: {
      zcash_unified_address: user.sub as string,
      display_name: (user.name as string) ?? null,
      username: (user.preferred_username as string) ?? null,
      picture: (user.picture as string) ?? null,
    },
    accessToken: tokens.access_token!,
    idToken: tokens.id_token,
  };
}

// ── TypeScript type for ZcashMe claims ────────────────────

export interface ZcashMeUser {
  display_name: string | null;
  username: string | null;
  picture: string | null;
  zcash_unified_address: string;
}