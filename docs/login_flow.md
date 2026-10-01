# Login Flow & Session Handling — SecureLLM-Enterprise v3

## Sequence (per-user login, Improvement 2)

```
Browser                    FastAPI                     company.db (users)
   │  POST /api/login          │                             │
   │  {username, password}     │                             │
   │──────────────────────────►│  SELECT * FROM users        │
   │                           │  WHERE username = ?  ───────►
   │                           │  ◄───────────────────────────│ row (bcrypt hash)
   │                           │  bcrypt.checkpw(pw, hash)    │
   │                           │  [row.is_active must be 1]   │
   │                           │  build JWT claims            │
   │  200 {access_token,       │  sign HS256 (secret from     │
   │   token_type, expires_in, │  env JWT_SECRET / secrets.json)
   │   user{...}}              │  audit.append(action=LOGIN)  │
   │◄──────────────────────────│  UPDATE last_login           │
   │  store token (session)    │                             │
   │  → redirect /dashboard    │                             │

Failure (bad password / unknown user / inactive):
   audit.append(action=DENIED, reason="invalid credentials")
   → 401 {"detail": "Invalid credentials"}
```

## JWT structure (60 minutes)

Header: `{"alg": "HS256", "typ": "JWT"}` — the algorithm is **pinned server-side**; a token claiming `alg: none` is rejected before decode.

```json
{
  "sub":  "hr_manager",
  "role": "HR_Manager",
  "dept": "HR",
  "clr":  "L4",
  "uid":  4,
  "name": "Anjali Verma",
  "iat":  1761906131,
  "exp":  1761909731,
  "jti":  "9f2c1e64d3a84f0e..."
}
```

- `exp - iat = 3600` seconds (`config/app_config.yaml → session.token_exp_minutes: 60`).
- `role` is the ONLY input the RBAC engine trusts; `clr` feeds the CIA-C clearance check.
- `jti` is the session id used by the CIA-A concurrent-session registry.
- Verification (`src/governance/auth.py::verify_token`) raises on tamper/expiry → 401 with the reason class (`invalid token: ExpiredSignatureError` / `DecodeError`).

## Token lifecycle & edge cases (all covered by tests)

| Case | Behaviour | Test |
|---|---|---|
| valid login | 200 + JWT + profile | `test_login.py::test_valid_login_returns_jwt_and_profile` |
| wrong password / unknown user | 401 `Invalid credentials` | `test_invalid_password_returns_401`, `test_unknown_user_returns_401` |
| inactive user (`is_active=0`) | 401 — account checked before hash verify | `test_inactive_user_cannot_login` |
| expired JWT | 401 `ExpiredSignatureError` | `test_expired_jwt_rejected` |
| missing Authorization header | 401 `missing bearer token` | `test_missing_and_malformed_jwt_rejected` |
| malformed JWT | 401 `DecodeError` | same |
| tampered JWT (1 char flipped) | 401 signature mismatch | `test_rbac.py::test_tampered_token_rejected` |
| `alg: none` forged token | 401 — algorithm pinning | `test_rbac.py::test_alg_none_token_rejected` |
| all 10 demo users | role + clearance as specified | `test_all_ten_demo_users_can_login` |

## Session handling

- **Stateless by default**: every protected endpoint resolves identity from the signed JWT only — no server-side session store needed for auth.
- **CIA-A session cap**: the first `/api/chat` call with a token registers its `jti` in the per-user session registry (TTL 60 min, matching the token expiry). A **4th distinct live session** for the same user is refused with `429 CIA-A` — stolen-credential floods cannot multiply sessions. Same token reuse is free (it is the same session).
- **Rate limit** (Layer 2a): 20 requests/min + 6k token budget per user; rejections are logged as CIA-A violations.
- **Login rate**: login attempts are audited (LOGIN / DENIED) but intentionally not rate-limited in the demo — production would add per-IP throttling + lockout + MFA (documented limitation).
- **Client storage**: the demo dashboard keeps the token in `sessionStorage` (cleared on tab close and on Sign out). Production guidance: httpOnly Secure cookie + refresh-token rotation.

## UI pages

| Page | Route | Purpose |
|---|---|---|
| `src/api/static/login.html` | `GET /login` | username/password form, error surface, demo-credential hint → redirects to `/dashboard` |
| `src/api/static/dashboard.html` | `GET /dashboard` | profile + effective access + own audit trail + chat; Admins additionally see system-wide stats (`/api/stats`) |
| `src/api/static/index.html` | `GET /` | single-file chat demo with identity dropdown (developer view) |

## Password storage

- Seeded accounts: **bcrypt cost 12** (`src/db/seed_users.py`). Verify: `SELECT password_hash FROM users` → all rows start with `$2b$12$` (asserted by `test_passwords_are_bcrypt_hashed_in_db`).
- The original `config/users.yaml` bootstrap (SHA-256) remains as a fallback so a fresh clone still authenticates before seeding; the constant-time comparison path is shared.
- Production: OIDC/SSO + MFA + per-user salted pepper via a KMS — the interface (`authenticate`) would swap, nothing else changes.
