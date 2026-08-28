# Patch Report

## Patch for: Broken object-level authorization (IDOR/BOLA)

- Status: applied
- Explanation: The original `/api/account` and `/api/users/:id` endpoints allowed any caller to retrieve arbitrary user data because they lacked authentication and ownership checks, leading to IDOR/BOLA vulnerabilities. The patch adds session handling by extracting the `session` cookie, verifying it against the server‑side `sessions` map, and ensuring the requested user ID matches the authenticated user's ID. Unauthorized requests now receive 401, and attempts to access another user's data receive 403, eliminating the object‑level authorization flaw while preserving existing functionality for legitimate owners.

```diff
--- before/server.js
+++ after/server.js
@@ -52,10 +52,23 @@
   res.json({ account: user });
 });
 
-// GET /api/users/:id — BOLA/IDOR: no authentication or ownership check
+// GET /api/users/:id — BOLA/IDOR: fixed with session ownership check
 app.get("/api/users/:id", (req, res) => {
-  // TODO: verify Authorization header and ownership
+  // Extract session token from cookies
+  const cookieHeader = req.headers.cookie || "";
+  const tokenMatch = cookieHeader.match(/(?:^|; )session=([^;]+)/);
+  const token = tokenMatch ? tokenMatch[1] : null;
+  if (!token || !sessions.has(token)) {
+    return res.status(401).json({ error: "unauthenticated" });
+  }
+  const requesterId = sessions.get(token);
+
   const id = Number(req.params.id);
+  // Enforce ownership: only allow access to own user record
+  if (id !== requesterId) {
+    return res.status(403).json({ error: "forbidden" });
+  }
+
   const user = db.users.find((u) => u.id === id);
   if (!user) {
     return res.status(404).json({ error: "not found" });
```
