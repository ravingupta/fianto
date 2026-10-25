# Surface: APIs and backend services (Express / Fastify / Nest / Koa / FastAPI / Flask / Lambda handlers)
Checklist
- Authorization on every route: missing middleware, IDOR (object ids from the request used without ownership checks), role checks, admin/sandbox routers mounted in production.
- Authentication: JWT verification options (algorithms pinned, audience/issuer checked, expiry), API-key comparison (timing-safe), session fixation, password hashing (bcrypt/argon2 vs md5/sha), reset-token entropy.
- Input handling: SQL/NoSQL/command injection, path traversal (path.join with user input), SSRF (axios/fetch to user-supplied URLs; cloud metadata), mass assignment (Object.assign/spread of req.body into models), prototype pollution.
- Trust proxy / rate limiting / IP allowlists that can be spoofed via X-Forwarded-For; CORS reflecting origin with credentials.
- File uploads: multer limits, content-type validation, storage paths, public bucket ACLs.
- Webhooks: signature verification (HMAC, timing-safe compare), replay protection, idempotency.
- Secrets and config: hard-coded vendor keys, .env committed, secrets logged, verbose error responses with stack traces.
- Data exposure: over-fetching in responses, PII in logs, debug endpoints.
- Dependency exposure that is reachable on request paths (express, body-parser, qs, axios, jws/jsonwebtoken, multer).
