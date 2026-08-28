# SentinelForge AI - Technical Findings Report

## Broken object-level authorization (IDOR/BOLA)

- **Severity:** HIGH · **Confidence:** 0.8 · **Status:** fixed
- **Category:** authorization · **Source:** dynamic · **Provenance:** Observed
- **Location:** server.js:41

**Description:**
Alternate object identifiers return different resources without authentication (http://127.0.0.1:3000/api/profile/1 vs http://127.0.0.1:3000/api/profile/2).

**Why it matters:** Users can read others' objects - classic IDOR. Server must enforce ownership.

**Patch status:** verified

---

## Missing authentication on sensitive route

- **Severity:** HIGH · **Confidence:** 0.7 · **Status:** open
- **Category:** authentication · **Source:** dynamic · **Provenance:** Observed
- **Location:** server.js:52

**Description:**
Route /api/admin/users returns data without authentication.

**Why it matters:** Sensitive endpoints reachable without authentication bypass access control.

---

## Browser console errors (1)

- **Severity:** MEDIUM · **Confidence:** 0.85 · **Status:** open
- **Category:** reliability · **Source:** browser · **Provenance:** Observed
- **Location:** n/a

**Description:**
JavaScript console errors observed while browsing: Failed to load resource: the server responded with a status of 404 (Not Found) (1)

---

## Missing HTTP security headers

- **Severity:** LOW · **Confidence:** 0.9 · **Status:** open
- **Category:** configuration · **Source:** dynamic · **Provenance:** Observed
- **Location:** n/a

**Description:**
HTTP Strict Transport Security (HSTS) is missing; Content-Security-Policy is missing; X-Content-Type-Options (nosniff) is missing; X-Frame-Options is missing (clickjacking risk); Referrer-Policy is missing.

**Why it matters:** Missing security headers weaken browser-side protections (XSS, clickjacking, MIME sniffing).

---
