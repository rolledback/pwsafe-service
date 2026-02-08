# E2E Tests

End-to-end tests for pwsafe-service. Tests run against a fully built server binary with real HTTP requests.

## Prerequisites

Build the backend and frontend before running tests:

```bash
# Build backend
cd backend && go build -o pwsafe-service.exe cmd/pwsafe-service/main.go  # Windows
cd backend && go build -o pwsafe-service cmd/pwsafe-service/main.go      # Linux/Mac

# Build frontend
cd frontend && npm run build
```

## Running Tests

```bash
cd e2e
npm install
npm test
```

## Architecture

Each test file starts its own server instance on an OS-assigned port with isolated temp directories. Tests run in parallel by default (vitest file-level parallelism).

- `src/api/user-flows/` — Tests that replicate frontend user interactions via API calls
- `src/api/security/` — Tests that verify security controls (token auth, path traversal, CORS, headers, rate limiting, etc.)
- `src/browser/` — Reserved for future Playwright browser tests
- `src/helpers/` — Server lifecycle management, typed API client, fixture helpers
