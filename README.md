# Auth Lab

A small Forge-native authentication application for testing account flows. It includes account creation, sign-in, sign-out, a protected success page, password change, and single-use password reset links.

## Run locally

1. Copy `.env.example` to `.env` if you want to override Compose defaults.
2. Run `docker compose up --build`.
3. Open <http://localhost:8080>.

In the default local test mode, a valid forgot-password submission shows the reset link on the result page. This is intentional for testing and must not be enabled in production.

## Commands

- `npm run typecheck` — type-check without output
- `npm test` — run unit tests
- `TEST_BASE_URL=http://127.0.0.1:8080 npm run test:e2e` — exercise the live authentication flow
- `npm run build` — compile production JavaScript
- `npm start` — start the compiled application (requires the variables in `.env.example`)

## Security notes

Passwords use Node's scrypt implementation with a unique salt. Sessions are server-side in PostgreSQL with HTTP-only, same-site cookies. State-changing forms require CSRF tokens, authentication endpoints are rate-limited, reset tokens are hashed at rest and expire after 30 minutes, and responses avoid account enumeration.
