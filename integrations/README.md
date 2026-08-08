# ZcashMe — Integration Guides

ZcashMe is a standard OpenID Connect provider at `auth.zcash.me`. Users prove wallet ownership by sending a 0.002 ZEC on-chain payment. Your app receives verified claims — no passwords, no third-party tracking.

**No SDK to install.** Your existing auth library talks to it directly via OIDC discovery.

## How it works

```
Your app                         auth.zcash.me                    User
  │                                    │                            │
  │  ── redirect to /auth ──────────>  │                            │
  │                                    │  ── shows payment page ──> │
  │                                    │  <── user pays 0.002 ZEC ──│
  │  <── redirect back with code ────  │                            │
  │                                    │                            │
  │  ── exchange code for tokens ───>  │                            │
  │  <── access_token + id_token ────  │                            │
  │                                    │                            │
  │  ── fetch /me (userinfo) ───────>  │                            │
  │  <── verified claims ────────────  │                            │
```

## OIDC Discovery

```
https://auth.zcash.me/.well-known/openid-configuration
```

Your auth library uses this to auto-discover endpoints (authorization, token, userinfo, JWKS).

## Claims

The userinfo endpoint (`/me`) returns:

| Claim | Type | Description |
|---|---|---|
| `sub` | `string` | Zcash unified address — the unique user ID |
| `name` | `string \| null` | Display name (e.g., "Paul Brigner") |
| `preferred_username` | `string \| null` | ZcashMe username (e.g., "paul_brigner") |
| `picture` | `string \| null` | Profile image URL |
| `zcash_unified_address` | `string` | Zcash unified address (same as `sub`) |

`sub` and `zcash_unified_address` carry the same value. `sub` is the OIDC standard name. `zcash_unified_address` is the Zcash-specific name. Use whichever your app prefers.

## The `user_id` parameter

Pass `user_id` as an extra query parameter in the authorization request to tag the user's ZcashMe profile. After verification, a link with this value as the label appears on their profile.

Use it for verification codes, handles, referral codes, or any identifier your app needs.

```
https://auth.zcash.me/auth?...&user_id=PGPZ-A3F2B1
```

How to pass it depends on your auth library — see the examples below.

## Integration Examples

| Platform | File | `user_id` method |
|---|---|---|
| **Better Auth** | [`better-auth.ts`](examples/better-auth.ts) | `authorizationUrlParams` |
| **NextAuth / Auth.js** | [`next-auth.ts`](examples/next-auth.ts) | `authorization.params` |
| **Clerk** | [`clerk.ts`](examples/clerk.ts) | Proxy (dashboard config) |
| **Raw OIDC** | [`oidc.ts`](examples/oidc.ts) | Manual URL param |

Each file is a self-contained, copy-paste integration guide with setup steps, server config, client code, and profile mapping.

## Auth Requirements

- **PKCE required** — no client secret
- **Scopes**: `openid profile`
- **Redirect URIs**: Must be registered in the auth service client config

## Registered Clients

Clients are hardcoded in the auth service. To add your app, submit a PR to [`provider.ts`](../auth-service/src/provider.ts).

| Client ID | App | Redirect URIs |
|---|---|---|
| `pgpz` | PGPZ Community | `https://community.pgpz.org/api/auth/callback/zcashme`, `http://localhost:3000/api/auth/callback/zcashme` |