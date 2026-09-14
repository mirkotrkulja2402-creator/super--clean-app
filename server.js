const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const QRCode = require("qrcode");

const PORT = Number(process.env.PORT || 3000);
const SESSION_DAYS = 7;
const BACKUP_DIR = path.resolve(
  process.env.BACKUP_DIR || path.join(__dirname, "backups")
);
const BACKUP_RETENTION_DAYS = 14;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL nije postavljen.");
}

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET mora imati najmanje 32 znaka.");
}

const app = express();
app.set("trust proxy", 1);
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.disable("x-powered-by");
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "https://unpkg.com"],
        styleSrc: ["'self'", "https://unpkg.com"],
        imgSrc: [
          "'self'",
          "data:",
          "blob:",
          "https://*.tile.openstreetmap.org",
        ],
        connectSrc: ["'self'", "https://nominatim.openstreetmap.org"],
      },
    },
  })
);
app.use(express.json({ limit: "32kb" }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Previše pokušaja prijave. Pokušaj ponovo kasnije." },
});

app.use(express.static(path.join(__dirname, "public")));

function hashToken(token) {
  return crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(token)
    .digest("hex");
}

function createSessionCookie(token) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `session=${encodeURIComponent(
    token
  )}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}${secure}`;
}

function clearSessionCookie() {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`;
}

function getCookie(request, name) {
  const header = request.headers.cookie || "";
  for (const part of header.split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) {
      return decodeURIComponent(value.join("="));
    }
  }
  return null;
}

async function writeAuditLog({ userId = null, username = "", role = "", action, method = "", pathName = "", statusCode = null, details = {}, }) {
  try {
    await pool.query(
      `INSERT INTO audit_logs
                (user_id, username, role, action, method, path, status_code, details)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
      [
        userId,
        username,
        role,
        action,
        method,
        pathName,
        statusCode,
        JSON.stringify(details),
      ]
    );
  } catch (error) {
    console.error("Audit zapis nije uspio:", error.message);
  }
}

function describeAuditAction(request) {
  const methodNames = {
    POST: "Kreiranje",
    PUT: "Izmjena",
    PATCH: "Izmjena",
    DELETE: "Brisanje",
  };
  return `${methodNames[request.method] || request.method} ${request.path}`;
}

function attachAudit(request, response) {
  if (!request.user || ["GET", "HEAD", "OPTIONS"].includes(request.method))
    return;

  response.on("finish", () => {
    void writeAuditLog({
      userId: request.user.id,
      username: request.user.username,
      role: request.user.role,
      action: describeAuditAction(request),
      method: request.method,
      pathName: request.path,
      statusCode: response.statusCode,
    });
  });
}

async function authenticate(request, response, next) {
  try {
    const token = getCookie(request, "session");
    if (!token) {
      return response.status(401).json({ error: "Nisi prijavljen." });
    }

    const result = await pool.query(
      `SELECT u.id, u.username, u.first_name, u.last_name, u.role
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1
               AND s.expires_at > NOW()
               AND u.is_active = TRUE`,
      [hashToken(token)]
    );

    if (result.rowCount !== 1) {
      return response.status(401).json({
        error: "Sesija je nevažeća ili je istekla.",
      });
    }

    request.user = result.rows[0];
    attachAudit(request, response);
    return next();
  } catch (error) {
    return next(error);
  }
}

function requireAdmin(request, response, next) {
  if (request.user.role !== "ADMIN") {
    return response.status(403).json({
      error: "Nemaš administratorsku dozvolu.",
    });
  }
  return next();
}

function requirePermission(permission) {
  return (request, response, next) => {
    if (request.user.role === "ADMIN") {
      return next();
    }

    return pool
      .query(
        `SELECT 1
             FROM role_permissions
             WHERE role_code = $1 AND permission_code = $2`,
        [request.user.role, permission]
      )
      .then((result) => {
        if (result.rowCount !== 1) {
          return response.status(403).json({
            error: "Nemaš dozvolu za ovu radnju.",
          });
        }
        return next();
      })
      .catch(next);
  };
}

function normalizeUserInput(body) {
  return {
    username: String(body.username || "").trim(),
    firstName: String(body.firstName || "").trim(),
    lastName: String(body.lastName || "").trim(),
    role: String(body.role || "")
      .trim()
      .toUpperCase(),
    password: String(body.password || ""),
    isActive: body.isActive !== false,
  };
}

function validateUserInput(input, isCreate) {
  if (!input.username || !input.firstName || !input.lastName || !input.role) {
    return "Popuni korisničko ime, ime, prezime i ulogu.";
  }

  if (!/^[a-zA-Z0-9._-]{3,100}$/.test(input.username)) {
    return "Korisničko ime mora imati 3–100 znakova i može sadržati slova, brojeve, tačku, crtu i donju crtu.";
  }

  if (isCreate && input.password.length < 8) {
    return "Lozinka mora imati najmanje 8 znakova.";
  }

  if (!isCreate && input.password && input.password.length < 8) {
    return "Nova lozinka mora imati najmanje 8 znakova.";
  }

  return null;
}

async function countActiveAdmins(client = pool) {
  const result = await client.query(
    `SELECT COUNT(*)::int AS count
         FROM users
         WHERE role = 'ADMIN' AND is_active = TRUE`
  );
  return result.rows[0].count;
}

async function ensureRoleExists(role) {
  const result = await pool.query("SELECT code FROM roles WHERE code = $1", [
    role,
  ]);
  return result.rowCount === 1;
}

function publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    firstName: row.first_name,
    lastName: row.last_name,
    role: row.role,
    roleName: row.role_name || row.role,
    isActive: row.is_active,
    createdAt: row.created_at,
  };
}

app.post("/api/login", loginLimiter, async (request, response, next) => {
  try {
    const username = String(request.body.username || "").trim();
    const password = String(request.body.password || "");

    if (!username || !password) {
      return response.status(400).json({
        error: "Unesi korisničko ime i lozinku.",
      });
    }

    const result = await pool.query(
      `SELECT id, username, password_hash, first_name, last_name, role
             FROM users
             WHERE username = $1 AND is_active = TRUE`,
      [username]
    );

    if (result.rowCount !== 1) {
      return response.status(401).json({
        error: "Pogrešno korisničko ime ili lozinka.",
      });
    }

    const user = result.rows[0];
    if (!(await bcrypt.compare(password, user.password_hash))) {
      return response.status(401).json({
        error: "Pogrešno korisničko ime ili lozinka.",
      });
    }

    const token = crypto.randomBytes(32).toString("base64url");
    await pool.query(
      `INSERT INTO sessions (user_id, token_hash, expires_at)
             VALUES ($1, $2, $3)`,
      [
        user.id,
        hashToken(token),
        new Date(Date.now() + SESSION_DAYS * 86400000),
      ]
    );

    response.setHeader("Set-Cookie", createSessionCookie(token));
    const permissionResult = await pool.query(
      `SELECT permission_code
             FROM role_permissions
             WHERE role_code = $1`,
      [user.role]
    );

    await writeAuditLog({
      userId: user.id,
      username: user.username,
      role: user.role,
      action: "Prijava u sistem",
      method: "POST",
      pathName: "/api/login",
      statusCode: 200,
    });

    return response.json({
      user: {
        id: user.id,
        username: user.username,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        permissions: permissionResult.rows.map((row) => row.permission_code),
      },
    });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/logout", authenticate, async (request, response, next) => {
  try {
    const token = getCookie(request, "session");
    if (token) {
      await pool.query("DELETE FROM sessions WHERE token_hash = $1", [
        hashToken(token),
      ]);
    }
    response.setHeader("Set-Cookie", clearSessionCookie());
    await writeAuditLog({
      userId: request.user.id,
      username: request.user.username,
      role: request.user.role,
      action: "Odjava iz sistema",
      method: "POST",
      pathName: "/api/logout",
      statusCode: 204,
    });
    return response.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.get("/api/me", authenticate, async (request, response, next) => {
  try {
    const result = await pool.query(
      "SELECT code, name FROM roles WHERE code = $1",
      [request.user.role]
    );
    const permissionResult = await pool.query(
      `SELECT permission_code
             FROM role_permissions
             WHERE role_code = $1`,
      [request.user.role]
    );

    response.json({
      user: {
        id: request.user.id,
        username: request.user.username,
        firstName: request.user.first_name,
        lastName: request.user.last_name,
        role: request.user.role,
        roleName: result.rows[0]?.name || request.user.role,
        permissions: permissionResult.rows.map((row) => row.permission_code),
      },
    });
  } catch (error) {
    next(error);
  }
});

app.get(
  "/api/admin/users",
  authenticate,
  requireAdmin,
  async (request, response, next) => {
    try {
      const result = await pool.query(
        `SELECT u.id, u.username, u.first_name, u.last_name, u.role,
                    u.is_active, u.created_at, r.name AS role_name
             FROM users u
             LEFT JOIN roles r ON r.code = u.role
             ORDER BY u.is_active DESC, u.first_name, u.last_name`
      );

      response.json({ users: result.rows.map(publicUser) });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  "/api/admin/roles",
  authenticate,
  requireAdmin,
  async (request, response, next) => {
    try {
      const roles = await pool.query(
        `SELECT code, name, description, is_system
             FROM roles
             ORDER BY is_system DESC, name`
      );

      const permissions = await pool.query(
        `SELECT code, name, module
             FROM permissions
             ORDER BY module, name`
      );

      const assignments = await pool.query(
        `SELECT role_code, permission_code FROM role_permissions`
      );

      const rolePermissions = {};
      for (const row of assignments.rows) {
        rolePermissions[row.role_code] ||= [];
        rolePermissions[row.role_code].push(row.permission_code);
      }

      response.json({
        roles: roles.rows.map((role) => ({
          ...role,
          permissions: rolePermissions[role.code] || [],
        })),
        permissions: permissions.rows,
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/admin/users",
  authenticate,
  requireAdmin,
  async (request, response, next) => {
    try {
      const input = normalizeUserInput(request.body);
      const validationError = validateUserInput(input, true);
      if (validationError) {
        return response.status(400).json({ error: validationError });
      }

      if (!(await ensureRoleExists(input.role))) {
        return response
          .status(400)
          .json({ error: "Izabrana uloga ne postoji." });
      }

      const passwordHash = await bcrypt.hash(input.password, 12);
      const result = await pool.query(
        `INSERT INTO users
                (username, password_hash, first_name, last_name, role, is_active)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, username, first_name, last_name, role, is_active, created_at`,
        [
          input.username,
          passwordHash,
          input.firstName,
          input.lastName,
          input.role,
          input.isActive,
        ]
      );

      return response.status(201).json({ user: publicUser(result.rows[0]) });
    } catch (error) {
      if (error.code === "23505") {
        return response.status(409).json({
          error: "To korisničko ime već postoji.",
        });
      }
      next(error);
    }
  }
);

app.put(
  "/api/admin/users/:id",
  authenticate,
  requireAdmin,
  async (request, response, next) => {
    const client = await pool.connect();

    try {
      const input = normalizeUserInput(request.body);
      const validationError = validateUserInput(input, false);
      if (validationError) {
        return response.status(400).json({ error: validationError });
      }

      if (!(await ensureRoleExists(input.role))) {
        return response
          .status(400)
          .json({ error: "Izabrana uloga ne postoji." });
      }

      await client.query("BEGIN");

      const currentResult = await client.query(
        "SELECT id, username, role, is_active FROM users WHERE id = $1 FOR UPDATE",
        [request.params.id]
      );

      if (currentResult.rowCount !== 1) {
        await client.query("ROLLBACK");
        return response.status(404).json({ error: "Korisnik nije pronađen." });
      }

      const current = currentResult.rows[0];
      const removingAdminAccess =
        current.role === "ADMIN" &&
        current.is_active &&
        (input.role !== "ADMIN" || !input.isActive);

      if (removingAdminAccess && (await countActiveAdmins(client)) <= 1) {
        await client.query("ROLLBACK");
        return response.status(409).json({
          error: "Ne možeš ukloniti posljednjeg aktivnog administratora.",
        });
      }

      if (
        current.id === request.user.id &&
        (input.role !== "ADMIN" || !input.isActive)
      ) {
        await client.query("ROLLBACK");
        return response.status(400).json({
          error: "Ne možeš sebi ukloniti administratorski pristup.",
        });
      }

      let result;
      if (input.password) {
        const passwordHash = await bcrypt.hash(input.password, 12);
        result = await client.query(
          `UPDATE users
                 SET username = $1, password_hash = $2, first_name = $3,
                     last_name = $4, role = $5, is_active = $6, updated_at = NOW()
                 WHERE id = $7
                 RETURNING id, username, first_name, last_name, role, is_active, created_at`,
          [
            input.username,
            passwordHash,
            input.firstName,
            input.lastName,
            input.role,
            input.isActive,
            request.params.id,
          ]
        );
      } else {
        result = await client.query(
          `UPDATE users
                 SET username = $1, first_name = $2, last_name = $3,
                     role = $4, is_active = $5, updated_at = NOW()
                 WHERE id = $6
                 RETURNING id, username, first_name, last_name, role, is_active, created_at`,
          [
            input.username,
            input.firstName,
            input.lastName,
            input.role,
            input.isActive,
            request.params.id,
          ]
        );
      }

      if (!input.isActive) {
        await client.query("DELETE FROM sessions WHERE user_id = $1", [
          request.params.id,
        ]);
      }

      await client.query("COMMIT");
      return response.json({ user: publicUser(result.rows[0]) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      if (error.code === "23505") {
        return response.status(409).json({
          error: "To korisničko ime već postoji.",
        });
      }
      next(error);
    } finally {
      client.release();
    }
  }
);

app.delete(
  "/api/admin/users/:id",
  authenticate,
  requireAdmin,
  async (request, response, next) => {
    const client = await pool.connect();

    try {
      if (request.params.id === request.user.id) {
        return response.status(400).json({
          error: "Ne možeš obrisati vlastiti administratorski nalog.",
        });
      }

      await client.query("BEGIN");
      const current = await client.query(
        "SELECT id, role, is_active FROM users WHERE id = $1 FOR UPDATE",
        [request.params.id]
      );

      if (current.rowCount !== 1) {
        await client.query("ROLLBACK");
        return response.status(404).json({ error: "Korisnik nije pronađen." });
      }

      if (
        current.rows[0].role === "ADMIN" &&
        current.rows[0].is_active &&
        (await countActiveAdmins(client)) <= 1
      ) {
        await client.query("ROLLBACK");
        return response.status(409).json({
          error: "Ne možeš obrisati posljednjeg aktivnog administratora.",
        });
      }

      await client.query("DELETE FROM users WHERE id = $1", [
        request.params.id,
      ]);
      await client.query("COMMIT");
      return response.status(204).end();
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      next(error);
    } finally {
      client.release();
    }
  }
);

app.put(
  "/api/admin/roles/:code",
  authenticate,
  requireAdmin,
  async (request, response, next) => {
    const client = await pool.connect();

    try {
      const code = String(request.params.code || "")
        .trim()
        .toUpperCase();
      const name = String(request.body.name || "").trim();
      const description = String(request.body.description || "").trim();
      const permissions = Array.isArray(request.body.permissions)
        ? request.body.permissions.map(String)
        : [];

      if (!name) {
        return response.status(400).json({ error: "Naziv uloge je obavezan." });
      }

      await client.query("BEGIN");

      const roleResult = await client.query(
        "SELECT code, is_system FROM roles WHERE code = $1 FOR UPDATE",
        [code]
      );

      if (roleResult.rowCount !== 1) {
        await client.query("ROLLBACK");
        return response.status(404).json({ error: "Uloga nije pronađena." });
      }

      const validPermissions = await client.query(
        `SELECT code FROM permissions WHERE code = ANY($1::text[])`,
        [permissions]
      );
      const validCodes = new Set(validPermissions.rows.map((row) => row.code));

      await client.query(
        `UPDATE roles
             SET name = $1, description = $2, updated_at = NOW()
             WHERE code = $3`,
        [name, description, code]
      );

      await client.query("DELETE FROM role_permissions WHERE role_code = $1", [
        code,
      ]);

      for (const permission of validCodes) {
        await client.query(
          `INSERT INTO role_permissions (role_code, permission_code)
                 VALUES ($1, $2)`,
          [code, permission]
        );
      }

      await client.query("COMMIT
