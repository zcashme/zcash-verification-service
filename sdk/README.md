# @zcashme/login

The official JavaScript/TypeScript SDK for ZcashMe Authentication.

This SDK provides a lightweight OpenID Connect (OIDC) client for integrating `auth.zcash.me` into your own applications. It securely handles PKCE generation, managing redirects, exchanging authorization codes for tokens, and fetching user profiles.

## Installation

```bash
npm install @zcashme/login
# or
pnpm add @zcashme/login
# or
yarn add @zcashme/login
```

## Quick Start

### 1. Initialize the Client

```typescript
import { ZcashMeAuth } from '@zcashme/login';

const auth = new ZcashMeAuth({
  clientId: 'pgpz',
  redirectUri: 'https://community.pgpz.org/callback',
  userId: 'PGPZ-A3F2B1',  // optional — your app's identifier for this user
});
```

### 2. Initiate Login (Redirect to ZcashMe)

```typescript
// Browser — stores PKCE state in sessionStorage, then redirects
await auth.loginWithRedirect();

// Or get the URL to handle the redirect manually
const authState = await auth.createAuthState();
const url = await auth.buildAuthorizationUrl(authState);
```

### 3. Handle the Callback

After the user approves, they're redirected back to your `redirectUri` with a `code`:

```typescript
// On your callback page — parses URL, validates state, exchanges code,
// validates nonce, fetches user info, stores session, returns it
const session = await auth.handleRedirectCallback();
console.log(session.user.sub);        // Zcash address
console.log(session.user.preferred_username);  // ZcashMe username
```

### 4. Check Session

```typescript
const session = auth.getSession();
if (session) {
  console.log('Logged in as', session.user.preferred_username);
} else {
  console.log('Not logged in');
}
```

## React Components

Optional React bindings are available at `@zcashme/login/react`:

```tsx
import { ZcashMeButton, useZcashMeCallback } from '@zcashme/login/react';

// Login button
<ZcashMeButton
  clientId="pgpz"
  redirectUri="https://community.pgpz.org/callback"
  userId="PGPZ-A3F2B1"
  label="Sign in with ZcashMe"
/>

// Callback hook (on your redirect page)
function CallbackPage() {
  const { session, error, isLoading } = useZcashMeCallback({
    clientId: 'pgpz',
    redirectUri: 'https://community.pgpz.org/callback',
  });

  if (isLoading) return <p>Loading...</p>;
  if (error) return <p>Error: {error}</p>;
  return <p>Welcome, {session?.user.preferred_username}!</p>;
}
```

## The `userId` Parameter

Optional and provider-agnostic. If your app sends `&user_id=PGPZ-A3F2B1` in the authorization request, the ZcashMe auth service adds a link to the user's ZcashMe profile after verification. The value can be a handle, email, verification code, referral code, or any identifier your app uses for the user.

## Configuration

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `clientId` | Yes | — | Your client ID registered in the auth service |
| `redirectUri` | Yes | — | Where to redirect after login (must match registered URI) |
| `domain` | No | `auth.zcash.me` | Auth server domain |
| `scopes` | No | `['openid', 'profile']` | OAuth scopes |
| `userId` | No | — | Your app's identifier for this user (see above) |

## License

ISC