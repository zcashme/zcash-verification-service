import type {
  ZcashMeOptions,
  TokenResponse,
  ZcashMeUser,
  AuthState,
  ZcashMeSession,
} from './types';
import { ZcashMeAuthError, ZcashMeCallbackError } from './types';
import { base64urlEncode, randomBytes, randomString, sha256 } from './crypto';

const SESSION_KEY = 'zcashme_session';
const STATE_KEY = 'zcashme_auth_state';

/**
 * ZcashMe OIDC Client
 *
 * Handles PKCE generation, authorization URL building, code exchange,
 * and user info fetching. Provider-agnostic — works with any app
 * registered in the ZcashMe auth service.
 *
 * @example
 * const auth = new ZcashMeAuth({
 *   clientId: 'pgpz',
 *   redirectUri: 'https://community.pgpz.org/callback',
 *   userId: 'PGPZ-A3F2B1',  // optional
 * });
 *
 * // Start login
 * await auth.loginWithRedirect();
 *
 * // On callback page
 * const session = await auth.handleRedirectCallback();
 * console.log(session.user.sub); // Zcash address
 */
export class ZcashMeAuth {
  private domain: string;
  private clientId: string;
  private redirectUri: string;
  private scopes: string[];
  private userId?: string;

  constructor(options: ZcashMeOptions) {
    const rawDomain = options.domain || 'auth.zcash.me';
    this.domain = rawDomain.replace(/\/$/, '');
    this.clientId = options.clientId;
    this.redirectUri = options.redirectUri;
    this.scopes = options.scopes || ['openid', 'profile'];
    this.userId = options.userId;
  }

  private get baseUrl(): string {
    return this.domain.startsWith('http') ? this.domain : `https://${this.domain}`;
  }

  // ── PKCE & State ────────────────────────────────────────

  /**
   * Generate PKCE state (code_verifier, state, nonce).
   * Store the result (e.g., in sessionStorage) to use in handleCallback().
   */
  async createAuthState(): Promise<AuthState> {
    return {
      codeVerifier: base64urlEncode(randomBytes(32)),
      state: randomString(16),
      nonce: randomString(16),
    };
  }

  /**
   * Build the authorization URL with PKCE, state, nonce, and optional user_id.
   * Redirect the user's browser to this URL to start the login flow.
   */
  async buildAuthorizationUrl(authState: AuthState): Promise<string> {
    const challengeBytes = await sha256(authState.codeVerifier);
    const codeChallenge = base64urlEncode(challengeBytes);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: this.scopes.join(' '),
      state: authState.state,
      nonce: authState.nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    if (this.userId) {
      params.append('user_id', this.userId);
    }

    return `${this.baseUrl}/auth?${params.toString()}`;
  }

  // ── Browser convenience ─────────────────────────────────

  /**
   * Generate state + build URL + redirect the browser.
   * Stores auth state in sessionStorage for handleRedirectCallback().
   * Browser-only.
   */
  async loginWithRedirect(): Promise<void> {
    if (typeof window === 'undefined') {
      throw new ZcashMeAuthError(
        'loginWithRedirect can only be used in a browser',
        'wrong_environment',
      );
    }

    const authState = await this.createAuthState();
    sessionStorage.setItem(STATE_KEY, JSON.stringify(authState));

    const url = await this.buildAuthorizationUrl(authState);
    window.location.assign(url);
  }

  /**
   * Parse the callback URL to extract code or error.
   */
  parseCallback(
    url: string,
  ): { code: string; state: string } | { error: string; errorDescription?: string } {
    const parsed = new URL(url);
    const code = parsed.searchParams.get('code');
    const state = parsed.searchParams.get('state');
    const error = parsed.searchParams.get('error');
    const errorDescription = parsed.searchParams.get('error_description');

    if (error) {
      return { error, errorDescription: errorDescription || undefined };
    }

    if (!code) {
      return { error: 'invalid_callback', errorDescription: 'No code in callback URL' };
    }

    return { code, state: state || '' };
  }

  /**
   * Full callback handling: parse URL, validate state, exchange code,
   * validate nonce, fetch user info, and return a session.
   *
   * Reads auth state from sessionStorage (set by loginWithRedirect).
   * Stores the resulting session in sessionStorage.
   * Browser-only.
   */
  async handleRedirectCallback(url?: string): Promise<ZcashMeSession> {
    if (typeof window === 'undefined') {
      throw new ZcashMeAuthError(
        'handleRedirectCallback can only be used in a browser',
        'wrong_environment',
      );
    }

    const callbackUrl = url || window.location.href;
    const result = this.parseCallback(callbackUrl);

    if ('error' in result) {
      throw new ZcashMeCallbackError(result.error, result.errorDescription);
    }

    // Validate state (CSRF protection)
    const stored = sessionStorage.getItem(STATE_KEY);
    if (!stored) {
      throw new ZcashMeAuthError(
        'No auth state found. Did you call loginWithRedirect first?',
        'missing_state',
      );
    }

    const authState = JSON.parse(stored) as AuthState;
    if (result.state !== authState.state) {
      throw new ZcashMeAuthError('State mismatch — possible CSRF attack', 'state_mismatch');
    }

    // Exchange code for tokens
    const tokens = await this.exchangeCode(result.code, authState.codeVerifier);

    // Validate nonce in ID token (if present)
    if (tokens.id_token) {
      const payload = decodeJwtPayload(tokens.id_token);
      if (payload.nonce && payload.nonce !== authState.nonce) {
        throw new ZcashMeAuthError('Nonce mismatch — possible replay attack', 'nonce_mismatch');
      }
    }

    // Fetch user info
    const user = await this.getUserInfo(tokens.access_token);

    // Build session
    const session: ZcashMeSession = {
      user,
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token,
      expiresAt: Date.now() + tokens.expires_in * 1000,
    };

    // Store and clean up
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
    sessionStorage.removeItem(STATE_KEY);

    return session;
  }

  // ── Token exchange ──────────────────────────────────────

  /**
   * Exchange an authorization code for tokens.
   * Requires the code_verifier from the stored AuthState (PKCE).
   */
  async exchangeCode(code: string, codeVerifier: string): Promise<TokenResponse> {
    const response = await fetch(`${this.baseUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: this.clientId,
        redirect_uri: this.redirectUri,
        code,
        code_verifier: codeVerifier,
      }),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new ZcashMeAuthError(
        `Token exchange failed (${response.status})`,
        'token_exchange_failed',
        response.status,
      );
    }

    return (await response.json()) as TokenResponse;
  }

  /**
   * Refresh an access token using a refresh token.
   */
  async refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
    const response = await fetch(`${this.baseUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.clientId,
        refresh_token: refreshToken,
      }),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new ZcashMeAuthError(
        `Token refresh failed (${response.status})`,
        'token_refresh_failed',
        response.status,
      );
    }

    return (await response.json()) as TokenResponse;
  }

  // ── UserInfo ────────────────────────────────────────────

  /**
   * Fetch user info using the access token.
   */
  async getUserInfo(accessToken: string): Promise<ZcashMeUser> {
    const response = await fetch(`${this.baseUrl}/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      throw new ZcashMeAuthError(
        `Failed to fetch user info (${response.status})`,
        'userinfo_failed',
        response.status,
      );
    }

    return (await response.json()) as ZcashMeUser;
  }

  // ── Session helpers (browser) ───────────────────────────

  /**
   * Get the stored session, if any. Returns null if expired or absent.
   * Browser-only.
   */
  getSession(): ZcashMeSession | null {
    if (typeof window === 'undefined') return null;

    const stored = sessionStorage.getItem(SESSION_KEY);
    if (!stored) return null;

    try {
      const session = JSON.parse(stored) as ZcashMeSession;
      if (Date.now() >= session.expiresAt) {
        sessionStorage.removeItem(SESSION_KEY);
        return null;
      }
      return session;
    } catch {
      return null;
    }
  }

  /**
   * Clear the stored session. Browser-only.
   */
  clearSession(): void {
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem(SESSION_KEY);
    }
  }

  /**
   * Check if the user is logged in (has a valid, non-expired session).
   * Browser-only.
   */
  isAuthenticated(): boolean {
    return this.getSession() !== null;
  }
}

// ── JWT helpers ────────────────────────────────────────────

/**
 * Decode a JWT payload without verifying the signature.
 * For nonce checking only — signature verification should be done
 * server-side using the JWKS endpoint if needed.
 */
function decodeJwtPayload(jwt: string): Record<string, any> {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new ZcashMeAuthError('Invalid ID token format', 'invalid_id_token');
  }

  const payloadB64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');

  // Browser
  if (typeof atob === 'function') {
    const json = atob(payloadB64);
    return JSON.parse(json);
  }
  // Node
  if (typeof Buffer !== 'undefined') {
    const json = Buffer.from(payloadB64, 'base64').toString('utf8');
    return JSON.parse(json);
  }

  throw new ZcashMeAuthError('No base64 decoder available', 'no_decoder');
}