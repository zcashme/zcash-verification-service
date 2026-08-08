export interface ZcashMeOptions {
  /** Auth server domain (default: auth.zcash.me) */
  domain?: string;
  /** Your client ID (registered in the auth service) */
  clientId: string;
  /** Where to redirect after login (must match registered redirect_uri) */
  redirectUri: string;
  /** OAuth scopes (default: ['openid', 'profile']) */
  scopes?: string[];
  /**
   * Optional — your app's identifier for this user.
   * If provided, a link with this value as the label is added
   * to the user's ZcashMe profile after verification.
   * Can be a handle, email, verification code, referral code, etc.
   */
  userId?: string;
}

export interface ZcashMeUser {
  /** Zcash address (the subject / unique identifier) */
  sub: string;
  /** Display name or username */
  name: string | null;
  /** ZcashMe username (e.g., "cryptowhale") */
  preferred_username: string | null;
  /** Profile image URL */
  picture: string | null;
  /** Zcash address (same as sub) */
  zcash_address: string;
  /** Profile URL (e.g., "zcash.me/cryptowhale") */
  zcashme_profile_url: string | null;
}

export interface TokenResponse {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

export interface AuthState {
  codeVerifier: string;
  state: string;
  nonce: string;
}

export interface ZcashMeSession {
  user: ZcashMeUser;
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt: number; // unix timestamp (ms)
}

// ── Errors ────────────────────────────────────────────────

export class ZcashMeAuthError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode?: number,
  ) {
    super(message);
    this.name = 'ZcashMeAuthError';
  }
}

export class ZcashMeCallbackError extends ZcashMeAuthError {
  constructor(
    public oauthError: string,
    description?: string,
  ) {
    super(
      description ? `${oauthError}: ${description}` : oauthError,
      'callback_error',
    );
    this.name = 'ZcashMeCallbackError';
  }
}