# Auth Lab

A small Forge-native authentication application for testing account flows. It restricts access to an exact configured email domain and requires a single-use email-verification link before the protected success page. It also includes sign-in, sign-out, password change, and password reset.

## Run locally

1. Copy `.env.example` to `.env` if you want to override Compose defaults.
2. Run `docker compose up --build`.
3. Open <http://localhost:8080>.

The default allowed domain is `shapira.xyz`. In local test mode, verification and password-reset links are shown on screen. This is intentional for testing and does not prove inbox ownership; configure an organization-approved transactional email provider before production use.

## Commands

- `npm run typecheck` — type-check without output
- `npm test` — run unit tests
- `TEST_BASE_URL=http://127.0.0.1:8080 npm run test:e2e` — exercise the live authentication flow
- `npm run build` — compile production JavaScript
- `npm start` — start the compiled application (requires the variables in `.env.example`)

## Security notes

Passwords use Node's scrypt implementation with a unique salt. Sessions are server-side in PostgreSQL with HTTP-only, same-site cookies. State-changing forms require CSRF tokens, authentication endpoints are rate-limited, verification and reset tokens are hashed at rest and single-use, and responses avoid account enumeration. Verification links expire after 15 minutes; reset links expire after 30 minutes.
