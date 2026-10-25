# Surface: Web frontend (React / Vite / Next / CRA / static)
Checklist
- Cross-origin trust: window.postMessage listeners (origin + source checks), iframes, CORS assumptions, OAuth/SSO bridges.
- XSS sinks: dangerouslySetInnerHTML, innerHTML, document.write, markdown/HTML renderers (showdown, marked) without sanitization, URL-driven content, template injection.
- Open redirects: ?redirect= / returnTo / next parameters, window.location assignment from untrusted input.
- Auth and session handling in the client: tokens in localStorage vs httpOnly cookies, token refresh flows, logout completeness, role checks done only client-side.
- Secrets in the bundle: API keys, Firebase/Amplify config, third-party tokens in src/, .env with REACT_APP_/VITE_/NEXT_PUBLIC_ prefixes committed, hard-coded endpoints with credentials.
- Dependency exposure that is actually reachable in the browser bundle (axios, lodash templates, DOMPurify versions, react-router).
- Security headers and CSP configuration (vite/next config, public/index.html meta), SRI on CDN scripts.
- Build/deploy scripts (scripts/*.mjs) that shell out with interpolated input.
Ignore: pure styling, dev-only tooling CVEs that never ship to the browser (say so if a lead is dev-only).
