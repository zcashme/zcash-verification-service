# ZcashMe Authentication — Integrations

ZcashMe is a standard OpenID Connect provider at `auth.zcash.me`. Users prove wallet ownership by sending a 0.002 ZEC on-chain payment. Your app receives verified claims — no passwords, no third-party tracking.

No SDK to install. Your existing auth library talks to it directly via OIDC discovery.

## Quick Reference

| | Better Auth | NextAuth | Clerk | Raw OIDC |
|---|---|---|---|---|
| Config | Code | Code | Dashboard | Code |
| PKCE | Auto | Auto | Toggle | Manual |
| `user_id` param | `authorizationUrlParams` | `authorization.params` | Proxy | Manual |
| Example | `better-auth.ts` | `next-auth.ts` | `clerk.ts` | `oidc.ts` |

## OIDC Discovery

```
https://auth.zcash.me/.well-known/openid-configuration
```

## Claims

| Claim | Description |
|-------|-------------|
| `sub` | Zcash unified address (unique ID) |
| `name` | Display name (e.g., "Paul Brigner") |
| `preferred_username` | ZcashMe username (e.g., "paul_brigner") |
| `picture` | Profile image URL |
| `zcash_unified_address` | Zcash unified address (same as sub) |

## `user_id` parameter (optional)

Pass `user_id` in the authorization request to add a link to the user's ZcashMe profile with this value as the label. Use it for verification codes, handles, or any identifier your app needs to verify on the profile.

Example: `user_id=PGPZ-A3F2B1` → a link labeled `PGPZ-A3F2B1` appears on the user's ZcashMe profile after verification.

## Examples

- **[`examples/better-auth.ts`](examples/better-auth.ts)** — genericOAuth plugin config
- **[`examples/next-auth.ts`](examples/next-auth.ts)** — OIDC provider config
- **[`examples/clerk.ts`](examples/clerk.ts)** — dashboard setup + proxy for user_id
- **[`examples/oidc.ts`](examples/oidc.ts)** — raw oauth4webapi, no auth library

## Registered Clients

Clients are hardcoded in the auth service. PKCE required, no client secret.

| Client ID | App | Redirect URI |
|-----------|-----|--------------|
| `pgpz` | PGPZ Community | `https://community.pgpz.org/api/auth/callback/zcashme` |

To add your app, submit a PR to the auth service client config.