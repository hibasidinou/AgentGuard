# AgentGuard React dashboard

Run `npm install` and `npm run dev` from this directory. Backend URL is `http://localhost:8000` (local lab only). Use Node.js 22 for the tested frontend workflow.

First provision the fictional Alice/Bob accounts and configure the backend signing secret following `docs/auth-sessions.md` in the repository root. Start FastAPI before signing in. Do not put passwords or signing secrets in frontend files.

- Sign in using a provisioned account. `/api/auth/me` supplies the displayed username and role; the server alone authorizes actions.
- The JWT is held in memory, sent as `Authorization: Bearer` to the API, and discarded on logout, expiration or page reload/navigation. There is no browser-persistent token or refresh token. Browser password-manager behavior is separate from JWT storage.
- The existing deterministic simulation and optional Ollama agent use authenticated requests without identity fields in the request body.
- Logout clears local data immediately and calls the server to revoke the session. If revocation cannot be confirmed, the interface says so. Reloading or navigating away does not revoke the server session; an unrevoked session can remain valid until expiration.
- Monitoring is still a global demo feed (`/api/events`). Hiding it before login is a UI choice, not backend access control. Per-user/role access awaits coordination with the monitoring owner.
- Use only loopback HTTP for this prototype; require HTTPS and review the frontend API origin for any nonlocal deployment. Memory storage does not defeat active XSS. Browser cancellation does not guarantee cancellation of server work already started.

## Verification

```sh
npm test        # Node built-in tests for the session controller; no npm dependencies needed
npm run build   # Vite compilation; requires installed dependencies
```

Controller tests use mocked HTTP responses and a fake clock. They do not exercise React rendering or prove real-browser behavior. For a browser smoke test, sign in as Alice, simulate a restricted read (deny), sign out, sign in as Bob (allow), and confirm the old response/prompt is cleared. Test invalid credentials, refresh/reload, and logout while chat is running. The backend test suite independently verifies actual JWT/SQLite enforcement.
