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
const BACKUP_DIR = path.resolve(process.env.BACKUP_DIR || path.join(__dirname, "backups"));
const BACKUP_RETENTION_DAYS = 14;

if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL nije postavljen.");
}

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
    throw new Error("SESSION_SECRET mora imati najmanje 32 znaka.");
}

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.disable("x-powered-by");
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://unpkg.com"],
            styleSrc: ["'self'", "https://unpkg.com"],
            imgSrc: ["'self'", "data:", "blob:", "https://*.tile.openstreetmap.org"],
            connectSrc: ["'self'", "https://nominatim.openstreetmap.org"],
        },
    },
}));
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
    return crypto.createHmac("sha256", process.env.SESSION_SECRET)
        .update(token)
        .digest("hex");
}

function createSessionCookie(token) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    return `session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}${secure}`;
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

async function writeAuditLog({ userId = null, username = "", role = "", action, method = "", pathName = "", statusCode = null, details = {} }) {
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
            ],
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
    if (!request.user || ["GET", "HEAD", "OPTIONS"].includes(request.method)) return;

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
            [hashToken(token)],
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

        return pool.query(
            `SELECT 1
             FROM role_permissions
             WHERE role_code = $1 AND permission_code = $2`,
            [request.user.role, permission],
        ).then((result) => {
            if (result.rowCount !== 1) {
                return response.status(403).json({
                    error: "Nemaš dozvolu za ovu radnju.",
                });
            }
            return next();
        }).catch(next);
    };
}

function normalizeUserInput(body) {
    return {
        username: String(body.username || "").trim(),
        firstName: String(body.firstName || "").trim(),
        lastName: String(body.lastName || "").trim(),
        role: String(body.role || "").trim().toUpperCase(),
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
         WHERE role = 'ADMIN' AND is_active = TRUE`,
    );
    return result.rows[0].count;
}

async function ensureRoleExists(role) {
    const result = await pool.query(
        "SELECT code FROM roles WHERE code = $1",
        [role],
    );
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
            [username],
        );

        if (result.rowCount !== 1) {
            return response.status(401).json({
                error: "Pogrešno korisničko ime ili lozinka.",
            });
        }

        const user = result.rows[0];
        if (!await bcrypt.compare(password, user.password_hash)) {
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
            ],
        );

        response.setHeader("Set-Cookie", createSessionCookie(token));
        const permissionResult = await pool.query(
            `SELECT permission_code
             FROM role_permissions
             WHERE role_code = $1`,
            [user.role],
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
            await pool.query(
                "DELETE FROM sessions WHERE token_hash = $1",
                [hashToken(token)],
            );
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
            [request.user.role],
        );
        const permissionResult = await pool.query(
            `SELECT permission_code
             FROM role_permissions
             WHERE role_code = $1`,
            [request.user.role],
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

app.get("/api/admin/users", authenticate, requireAdmin, async (request, response, next) => {
    try {
        const result = await pool.query(
            `SELECT u.id, u.username, u.first_name, u.last_name, u.role,
                    u.is_active, u.created_at, r.name AS role_name
             FROM users u
             LEFT JOIN roles r ON r.code = u.role
             ORDER BY u.is_active DESC, u.first_name, u.last_name`,
        );

        response.json({ users: result.rows.map(publicUser) });
    } catch (error) {
        next(error);
    }
});

app.get("/api/admin/roles", authenticate, requireAdmin, async (request, response, next) => {
    try {
        const roles = await pool.query(
            `SELECT code, name, description, is_system
             FROM roles
             ORDER BY is_system DESC, name`,
        );

        const permissions = await pool.query(
            `SELECT code, name, module
             FROM permissions
             ORDER BY module, name`,
        );

        const assignments = await pool.query(
            `SELECT role_code, permission_code FROM role_permissions`,
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
});

app.post("/api/admin/users", authenticate, requireAdmin, async (request, response, next) => {
    try {
        const input = normalizeUserInput(request.body);
        const validationError = validateUserInput(input, true);
        if (validationError) {
            return response.status(400).json({ error: validationError });
        }

        if (!await ensureRoleExists(input.role)) {
            return response.status(400).json({ error: "Izabrana uloga ne postoji." });
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
            ],
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
});

app.put("/api/admin/users/:id", authenticate, requireAdmin, async (request, response, next) => {
    const client = await pool.connect();

    try {
        const input = normalizeUserInput(request.body);
        const validationError = validateUserInput(input, false);
        if (validationError) {
            return response.status(400).json({ error: validationError });
        }

        if (!await ensureRoleExists(input.role)) {
            return response.status(400).json({ error: "Izabrana uloga ne postoji." });
        }

        await client.query("BEGIN");

        const currentResult = await client.query(
            "SELECT id, username, role, is_active FROM users WHERE id = $1 FOR UPDATE",
            [request.params.id],
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

        if (removingAdminAccess && await countActiveAdmins(client) <= 1) {
            await client.query("ROLLBACK");
            return response.status(409).json({
                error: "Ne možeš ukloniti posljednjeg aktivnog administratora.",
            });
        }

        if (current.id === request.user.id &&
            (input.role !== "ADMIN" || !input.isActive)) {
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
                ],
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
                ],
            );
        }

        if (!input.isActive) {
            await client.query(
                "DELETE FROM sessions WHERE user_id = $1",
                [request.params.id],
            );
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
});

app.delete("/api/admin/users/:id", authenticate, requireAdmin, async (request, response, next) => {
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
            [request.params.id],
        );

        if (current.rowCount !== 1) {
            await client.query("ROLLBACK");
            return response.status(404).json({ error: "Korisnik nije pronađen." });
        }

        if (current.rows[0].role === "ADMIN" &&
            current.rows[0].is_active &&
            await countActiveAdmins(client) <= 1) {
            await client.query("ROLLBACK");
            return response.status(409).json({
                error: "Ne možeš obrisati posljednjeg aktivnog administratora.",
            });
        }

        await client.query("DELETE FROM users WHERE id = $1", [request.params.id]);
        await client.query("COMMIT");
        return response.status(204).end();
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        next(error);
    } finally {
        client.release();
    }
});

app.put("/api/admin/roles/:code", authenticate, requireAdmin, async (request, response, next) => {
    const client = await pool.connect();

    try {
        const code = String(request.params.code || "").trim().toUpperCase();
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
            [code],
        );

        if (roleResult.rowCount !== 1) {
            await client.query("ROLLBACK");
            return response.status(404).json({ error: "Uloga nije pronađena." });
        }

        const validPermissions = await client.query(
            `SELECT code FROM permissions WHERE code = ANY($1::text[])`,
            [permissions],
        );
        const validCodes = new Set(validPermissions.rows.map((row) => row.code));

        await client.query(
            `UPDATE roles
             SET name = $1, description = $2, updated_at = NOW()
             WHERE code = $3`,
            [name, description, code],
        );

        await client.query(
            "DELETE FROM role_permissions WHERE role_code = $1",
            [code],
        );

        for (const permission of validCodes) {
            await client.query(
                `INSERT INTO role_permissions (role_code, permission_code)
                 VALUES ($1, $2)`,
                [code, permission],
            );
        }

        await client.query("COMMIT");
        return response.json({ ok: true });
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        if (error.code === "23505") {
            return response.status(409).json({ error: "Naziv uloge već postoji." });
        }
        next(error);
    } finally {
        client.release();
    }
});

app.post("/api/admin/roles", authenticate, requireAdmin, async (request, response, next) => {
    try {
        const name = String(request.body.name || "").trim();
        const description = String(request.body.description || "").trim();
        const permissions = Array.isArray(request.body.permissions)
            ? request.body.permissions.map(String)
            : [];

        if (!name) {
            return response.status(400).json({ error: "Naziv uloge je obavezan." });
        }

        const code = name
            .toUpperCase()
            .replace(/[^A-Z0-9]+/g, "_")
            .replace(/^_+|_+$/g, "")
            .slice(0, 50);

        if (!code || code === "ADMIN") {
            return response.status(400).json({ error: "Naziv uloge nije dozvoljen." });
        }

        const client = await pool.connect();
        try {
            await client.query("BEGIN");

            await client.query(
                `INSERT INTO roles (code, name, description, is_system)
                 VALUES ($1, $2, $3, FALSE)`,
                [code, name, description],
            );

            const valid = await client.query(
                `SELECT code FROM permissions WHERE code = ANY($1::text[])`,
                [permissions],
            );

            for (const row of valid.rows) {
                await client.query(
                    `INSERT INTO role_permissions (role_code, permission_code)
                     VALUES ($1, $2)`,
                    [code, row.code],
                );
            }

            await client.query("COMMIT");
            return response.status(201).json({ code, name, description });
        } catch (error) {
            await client.query("ROLLBACK").catch(() => {});
            if (error.code === "23505") {
                return response.status(409).json({
                    error: "Uloga sa tim nazivom već postoji.",
                });
            }
            throw error;
        } finally {
            client.release();
        }
    } catch (error) {
        next(error);
    }
});

app.delete("/api/admin/roles/:code", authenticate, requireAdmin, async (request, response, next) => {
    try {
        const code = String(request.params.code || "").trim().toUpperCase();

        const role = await pool.query(
            "SELECT code, is_system FROM roles WHERE code = $1",
            [code],
        );

        if (role.rowCount !== 1) {
            return response.status(404).json({ error: "Uloga nije pronađena." });
        }

        if (role.rows[0].is_system || code === "ADMIN") {
            return response.status(400).json({
                error: "Sistemske uloge nije moguće obrisati.",
            });
        }

        const users = await pool.query(
            "SELECT COUNT(*)::int AS count FROM users WHERE role = $1",
            [code],
        );

        if (users.rows[0].count > 0) {
            return response.status(409).json({
                error: "Uloga se koristi kod korisnika. Prvo promijeni njihove uloge.",
            });
        }

        await pool.query("DELETE FROM roles WHERE code = $1", [code]);
        return response.status(204).end();
    } catch (error) {
        next(error);
    }
});



function normalizeOrderInput(body) {
    return {
        customerId: String(body.customerId || "").trim(),
        orderDate: String(body.orderDate || "").trim(),
        note: String(body.note || "").trim(),
        status: String(body.status || "RECEIVED").trim().toUpperCase(),
    };
}

function normalizeOrderItemInput(body) {
    return {
        serviceName: String(body.serviceName || "").trim(),
        unit: String(body.unit || "").trim().toLowerCase(),
        lengthM: body.lengthM === "" || body.lengthM == null ? null : Number(body.lengthM),
        widthM: body.widthM === "" || body.widthM == null ? null : Number(body.widthM),
        quantity: Number(body.quantity),
        unitPrice: Number(body.unitPrice),
        note: String(body.itemNote || "").trim(),
    };
}

function validateOrderInput(input) {
    if (!input.customerId) return "Izaberi kupca.";
    if (input.orderDate && !/^\\d{4}-\\d{2}-\\d{2}$/.test(input.orderDate)) {
        return "Datum narudžbe nije ispravan.";
    }
    if (!["RECEIVED", "WASHING", "DRYING", "READY", "DELIVERED", "PAID", "CANCELLED"].includes(input.status)) {
        return "Status narudžbe nije ispravan.";
    }
    if (input.note.length > 5000) return "Napomena može imati najviše 5000 znakova.";
    return null;
}

function validateOrderItemInput(input) {
    if (!input.serviceName) return "Unesi uslugu.";
    if (!["m2", "piece"].includes(input.unit)) return "Jedinica naplate nije ispravna.";
    if (!Number.isFinite(input.quantity) || input.quantity <= 0 || input.quantity > 100000) {
        return "Količina mora biti veća od nule.";
    }
    if (!Number.isFinite(input.unitPrice) || input.unitPrice < 0 || input.unitPrice > 1000000) {
        return "Cijena nije ispravna.";
    }

    if (input.unit === "m2") {
        if (!Number.isFinite(input.lengthM) || input.lengthM <= 0 ||
            !Number.isFinite(input.widthM) || input.widthM <= 0) {
            return "Za naplatu po m² unesi dužinu i širinu.";
        }
    } else {
        input.lengthM = null;
        input.widthM = null;
    }

    return null;
}

function publicOrder(row) {
    return {
        id: row.id,
        orderNumber: Number(row.order_number),
        orderCode: `N${Number(row.order_number)}`,
        customerId: row.customer_id,
        customerName: row.customer_name,
        phone: row.phone,
        address: row.address,
        city: row.city,
        latitude: row.latitude === null ? null : Number(row.latitude),
        longitude: row.longitude === null ? null : Number(row.longitude),
        orderDate: row.order_date,
        status: row.status,
        note: row.note,
        deliveryPrice: Number(row.delivery_price || 0),
        deliveryRequested: Number(row.delivery_price || 0) > 0,
        invoiceId: row.invoice_id || null,
        invoiceNumber: row.invoice_no === null || row.invoice_no === undefined
            ? null : Number(row.invoice_no),
        invoiceStatus: row.invoice_status || null,
        invoicePaymentMethod: row.invoice_payment_method || null,
        invoiceIssuedAt: row.invoice_issued_at || null,
        invoiceDueDate: row.invoice_due_date || null,
        itemsTotal: Number(row.items_total || 0),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

function publicOrderItem(row) {
    return {
        id: row.id,
        orderId: row.order_id,
        serviceName: row.service_name,
        unit: row.unit,
        lengthM: row.length_m === null ? null : Number(row.length_m),
        widthM: row.width_m === null ? null : Number(row.width_m),
        quantity: Number(row.quantity),
        unitPrice: Number(row.unit_price),
        areaM2: row.area_m2 === null ? null : Number(row.area_m2),
        total: Number(row.total),
        note: row.note || "",
        qrScanCount: Number(row.qr_scan_count || 0),
        lastQrScannedAt: row.last_qr_scanned_at || null,
    };
}

function normalizeCustomerInput(body) {
    return {
        firstName: String(body.firstName || "").trim(),
        lastName: String(body.lastName || "").trim(),
        companyName: String(body.companyName || "").trim(),
        phone: String(body.phone || "").trim(),
        whatsapp: String(body.whatsapp || "").trim(),
        address: String(body.address || "").trim(),
        city: String(body.city || "").trim(),
        note: String(body.note || "").trim(),
        latitude: body.latitude === null || body.latitude === undefined || body.latitude === ""
            ? null : Number(body.latitude),
        longitude: body.longitude === null || body.longitude === undefined || body.longitude === ""
            ? null : Number(body.longitude),
        isActive: body.isActive !== false,
    };
}

function validateCustomerInput(input) {
    if (!input.firstName) {
        return "Ime kupca je obavezno.";
    }

    if (input.firstName.length > 100 || input.lastName.length > 100) {
        return "Ime i prezime mogu imati najviše 100 znakova.";
    }

    if (input.companyName.length > 200 || input.address.length > 250 ||
        input.city.length > 100) {
        return "Jedno od polja je predugačko.";
    }

    if (input.phone.length > 40 || input.whatsapp.length > 40) {
        return "Broj telefona može imati najviše 40 znakova.";
    }

    if (input.note.length > 5000) {
        return "Napomena može imati najviše 5000 znakova.";
    }

    const coordinatesProvided = input.latitude !== null || input.longitude !== null;
    if (coordinatesProvided) {
        if (!Number.isFinite(input.latitude) || !Number.isFinite(input.longitude)) {
            return "Lokacija na mapi nije ispravna.";
        }
        if (input.latitude < -90 || input.latitude > 90 ||
            input.longitude < -180 || input.longitude > 180) {
            return "Lokacija na mapi nije ispravna.";
        }
    }

    return null;
}

function publicCustomer(row) {
    return {
        id: row.id,
        firstName: row.first_name,
        lastName: row.last_name,
        companyName: row.company_name,
        phone: row.phone,
        whatsapp: row.whatsapp,
        address: row.address,
        city: row.city,
        note: row.note,
        latitude: row.latitude === null ? null : Number(row.latitude),
        longitude: row.longitude === null ? null : Number(row.longitude),
        isActive: row.is_active,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

app.get("/api/customers", authenticate, requirePermission("customers.view"), async (request, response, next) => {
    try {
        const search = String(request.query.search || "").trim();
        const values = [];
        let where = "WHERE is_active = TRUE";

        if (search) {
            values.push(`%${search}%`);
            where += ` AND (
                first_name ILIKE $1 OR last_name ILIKE $1 OR company_name ILIKE $1
                OR phone ILIKE $1 OR whatsapp ILIKE $1 OR address ILIKE $1 OR city ILIKE $1
            )`;
        }

        const result = await pool.query(
            `SELECT id, first_name, last_name, company_name, phone, whatsapp,
                    address, city, note, latitude, longitude, is_active, created_at, updated_at
             FROM customers
             ${where}
             ORDER BY first_name, last_name
             LIMIT 200`,
            values,
        );

        response.json({ customers: result.rows.map(publicCustomer) });
    } catch (error) {
        next(error);
    }
});

app.get("/api/customers/:id", authenticate, requirePermission("customers.view"), async (request, response, next) => {
    try {
        const result = await pool.query(
            `SELECT id, first_name, last_name, company_name, phone, whatsapp,
                    address, city, note, latitude, longitude, is_active, created_at, updated_at
             FROM customers
             WHERE id = $1`,
            [request.params.id],
        );

        if (result.rowCount !== 1) {
            return response.status(404).json({ error: "Kupac nije pronađen." });
        }

        return response.json({ customer: publicCustomer(result.rows[0]) });
    } catch (error) {
        return next(error);
    }
});


app.get("/api/customers/:id/history", authenticate, requirePermission("customers.view"), async (request, response, next) => {
    try {
        const customerResult = await pool.query(
            `SELECT id, first_name, last_name, company_name, phone, whatsapp,
                    address, city, note, latitude, longitude, is_active, created_at, updated_at
             FROM customers
             WHERE id = $1`,
            [request.params.id],
        );

        if (customerResult.rowCount !== 1) {
            return response.status(404).json({ error: "Kupac nije pronađen." });
        }

        const ordersResult = await pool.query(
            `SELECT o.id, o.order_number, o.order_date, o.note, o.delivery_price,
                    COALESCE(items.item_count, 0) AS item_count,
                    COALESCE(items.items_total, 0) AS items_total,
                    i.id AS invoice_id, i.invoice_no, i.status AS invoice_status,
                    i.payment_method AS invoice_payment_method, i.issued_at AS invoice_issued_at
             FROM orders o
             LEFT JOIN invoices i ON i.order_id = o.id
             LEFT JOIN LATERAL (
                 SELECT COUNT(*)::int AS item_count,
                        COALESCE(SUM(oi.total), 0) AS items_total
                 FROM order_items oi
                 WHERE oi.order_id = o.id
             ) items ON TRUE
             WHERE o.customer_id = $1
             ORDER BY o.order_date DESC, o.order_number DESC
             LIMIT 200`,
            [request.params.id],
        );

        const totalsResult = await pool.query(
            `SELECT COUNT(DISTINCT o.id)::int AS order_count,
                    COALESCE(SUM(COALESCE(items.item_count, 0)), 0)::int AS carpet_count,
                    COALESCE(SUM(CASE WHEN i.status = 'INVOICED'
                                      THEN COALESCE(items.items_total, 0) + o.delivery_price
                                      ELSE 0 END), 0) AS total_spent,
                    COALESCE(SUM(CASE WHEN i.status = 'INVOICED'
                                      THEN o.delivery_price ELSE 0 END), 0) AS total_delivery
             FROM orders o
             LEFT JOIN invoices i ON i.order_id = o.id
             LEFT JOIN LATERAL (
                 SELECT COUNT(*)::int AS item_count,
                        COALESCE(SUM(oi.total), 0) AS items_total
                 FROM order_items oi
                 WHERE oi.order_id = o.id
             ) items ON TRUE
             WHERE o.customer_id = $1`,
            [request.params.id],
        );

        const customer = publicCustomer(customerResult.rows[0]);
        const totals = totalsResult.rows[0];

        return response.json({
            customer,
            totals: {
                orderCount: Number(totals.order_count || 0),
                carpetCount: Number(totals.carpet_count || 0),
                totalSpent: Number(totals.total_spent || 0),
                totalDelivery: Number(totals.total_delivery || 0),
            },
            orders: ordersResult.rows.map((row) => ({
                id: row.id,
                orderNumber: Number(row.order_number),
                orderCode: `N${Number(row.order_number)}`,
                orderDate: row.order_date,
                itemCount: Number(row.item_count || 0),
                itemsTotal: Number(row.items_total || 0),
                deliveryPrice: Number(row.delivery_price || 0),
                total: Number(row.items_total || 0) + Number(row.delivery_price || 0),
                note: row.note || "",
                invoiceId: row.invoice_id || null,
                invoiceNumber: row.invoice_no === null || row.invoice_no === undefined
                    ? null : Number(row.invoice_no),
                invoiceStatus: row.invoice_status || null,
                invoicePaymentMethod: row.invoice_payment_method || null,
                invoiceIssuedAt: row.invoice_issued_at || null,
                invoiceDueDate: row.invoice_due_date || null,
            })),
        });
    } catch (error) {
        return next(error);
    }
});

app.post("/api/customers", authenticate, requirePermission("customers.create"), async (request, response, next) => {
    try {
        const input = normalizeCustomerInput(request.body);
        const validationError = validateCustomerInput(input);
        if (validationError) {
            return response.status(400).json({ error: validationError });
        }

        const result = await pool.query(
            `INSERT INTO customers
                (first_name, last_name, company_name, phone, whatsapp, address, city, note,
                 latitude, longitude, is_active)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             RETURNING id, first_name, last_name, company_name, phone, whatsapp,
                       address, city, note, latitude, longitude, is_active, created_at, updated_at`,
            [
                input.firstName, input.lastName, input.companyName, input.phone,
                input.whatsapp, input.address, input.city || "Banja Luka",
                input.note, input.latitude, input.longitude, input.isActive,
            ],
        );

        return response.status(201).json({
            customer: publicCustomer(result.rows[0]),
        });
    } catch (error) {
        return next(error);
    }
});

app.put("/api/customers/:id", authenticate, requirePermission("customers.edit"), async (request, response, next) => {
    try {
        const input = normalizeCustomerInput(request.body);
        const validationError = validateCustomerInput(input);
        if (validationError) {
            return response.status(400).json({ error: validationError });
        }

        const result = await pool.query(
            `UPDATE customers
             SET first_name = $1, last_name = $2, company_name = $3, phone = $4,
                 whatsapp = $5, address = $6, city = $7, note = $8,
                 latitude = $9, longitude = $10, is_active = $11, updated_at = NOW()
             WHERE id = $12
             RETURNING id, first_name, last_name, company_name, phone, whatsapp,
                       address, city, note, latitude, longitude, is_active, created_at, updated_at`,
            [
                input.firstName, input.lastName, input.companyName, input.phone,
                input.whatsapp, input.address, input.city || "Banja Luka",
                input.note, input.latitude, input.longitude, input.isActive, request.params.id,
            ],
        );

        if (result.rowCount !== 1) {
            return response.status(404).json({ error: "Kupac nije pronađen." });
        }

        return response.json({ customer: publicCustomer(result.rows[0]) });
    } catch (error) {
        return next(error);
    }
});

app.delete("/api/customers/:id", authenticate, requirePermission("customers.delete"), async (request, response, next) => {
    try {
        const result = await pool.query(
            "DELETE FROM customers WHERE id = $1 RETURNING id",
            [request.params.id],
        );

        if (result.rowCount !== 1) {
            return response.status(404).json({ error: "Kupac nije pronađen." });
        }

        return response.status(204).end();
    } catch (error) {
        return next(error);
    }
});



function normalizePriceInput(body) {
    return {
        serviceName: String(body.serviceName || "").trim(),
        unit: String(body.unit || "").trim().toLowerCase(),
        price: Number(body.price),
        isActive: body.isActive !== false,
        sortOrder: Number(body.sortOrder || 0),
    };
}

function validatePriceInput(input) {
    if (!input.serviceName || input.serviceName.length > 200) {
        return "Naziv usluge je obavezan i može imati najviše 200 znakova.";
    }
    if (!["m2", "piece"].includes(input.unit)) {
        return "Jedinica mora biti m² ili komad.";
    }
    if (!Number.isFinite(input.price) || input.price < 0 || input.price > 1000000) {
        return "Cijena mora biti između 0 i 1.000.000 KM.";
    }
    if (!Number.isInteger(input.sortOrder) || input.sortOrder < 0 || input.sortOrder > 1000000) {
        return "Redoslijed nije ispravan.";
    }
    return null;
}

function publicPrice(row) {
    return {
        id: row.id,
        serviceName: row.service_name,
        unit: row.unit,
        price: Number(row.price),
        isActive: row.is_active,
        sortOrder: Number(row.sort_order),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

app.get("/api/pricing", authenticate, requirePermission("pricing.view"), async (request, response, next) => {
    try {
        const result = await pool.query(
            `SELECT id, service_name, unit, price, is_active, sort_order, created_at, updated_at
             FROM price_list
             ORDER BY sort_order, service_name`,
        );
        return response.json({ prices: result.rows.map(publicPrice) });
    } catch (error) {
        return next(error);
    }
});

app.post("/api/pricing", authenticate, requirePermission("pricing.edit"), async (request, response, next) => {
    try {
        const input = normalizePriceInput(request.body);
        const validationError = validatePriceInput(input);
        if (validationError) return response.status(400).json({ error: validationError });

        const result = await pool.query(
            `INSERT INTO price_list (service_name, unit, price, is_active, sort_order)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, service_name, unit, price, is_active, sort_order, created_at, updated_at`,
            [input.serviceName, input.unit, input.price.toFixed(2), input.isActive, input.sortOrder],
        );

        return response.status(201).json({ price: publicPrice(result.rows[0]) });
    } catch (error) {
        if (error.code === "23505") {
            return response.status(409).json({ error: "Ova usluga već postoji za izabranu jedinicu." });
        }
        return next(error);
    }
});

app.put("/api/pricing/:id", authenticate, requirePermission("pricing.edit"), async (request, response, next) => {
    try {
        const input = normalizePriceInput(request.body);
        const validationError = validatePriceInput(input);
        if (validationError) return response.status(400).json({ error: validationError });

        const result = await pool.query(
            `UPDATE price_list
             SET service_name = $1,
                 unit = $2,
                 price = $3,
                 is_active = $4,
                 sort_order = $5,
                 updated_at = NOW()
             WHERE id = $6
             RETURNING id, service_name, unit, price, is_active, sort_order, created_at, updated_at`,
            [input.serviceName, input.unit, input.price.toFixed(2), input.isActive, input.sortOrder, request.params.id],
        );

        if (result.rowCount !== 1) {
            return response.status(404).json({ error: "Stavka cjenovnika nije pronađena." });
        }

        return response.json({ price: publicPrice(result.rows[0]) });
    } catch (error) {
        if (error.code === "23505") {
            return response.status(409).json({ error: "Ova usluga već postoji za izabranu jedinicu." });
        }
        return next(error);
    }
});

app.delete("/api/pricing/:id", authenticate, requirePermission("pricing.edit"), async (request, response, next) => {
    try {
        const result = await pool.query(
            `UPDATE price_list
             SET is_active = FALSE, updated_at = NOW()
             WHERE id = $1
             RETURNING id`,
            [request.params.id],
        );

        if (result.rowCount !== 1) {
            return response.status(404).json({ error: "Stavka cjenovnika nije pronađena." });
        }

        return response.status(204).end();
    } catch (error) {
        return next(error);
    }
});

app.get("/api/qr/order/:orderId/item/:itemId", authenticate, requirePermission("qr.view"), async (request, response, next) => {
    try {
        const result = await pool.query(
            `SELECT o.id AS order_id, o.order_number, oi.id AS item_id
             FROM orders o
             JOIN order_items oi ON oi.order_id = o.id
             WHERE o.id = $1 AND oi.id = $2`,
            [request.params.orderId, request.params.itemId],
        );

        if (result.rowCount !== 1) {
            return response.status(404).json({ error: "Stavka za QR kod nije pronađena." });
        }

        const baseUrl = `${request.protocol}://${request.get("host")}`;
        const targetUrl = `${baseUrl}/?order=${encodeURIComponent(result.rows[0].order_id)}&item=${encodeURIComponent(result.rows[0].item_id)}`;
        const png = await QRCode.toBuffer(targetUrl, {
            type: "png",
            width: 360,
            margin: 2,
            errorCorrectionLevel: "M",
        });

        response.setHeader("Content-Type", "image/png");
        response.setHeader("Cache-Control", "private, max-age=300");
        return response.send(png);
    } catch (error) {
        return next(error);
    }
});

app.post("/api/qr/order/:orderId/item/:itemId/scan", authenticate, requirePermission("qr.view"), async (request, response, next) => {
    try {
        const result = await pool.query(
            `UPDATE order_items AS oi
             SET qr_scan_count = oi.qr_scan_count + 1,
                 last_qr_scanned_at = NOW()
             FROM orders AS o
             WHERE oi.id = $1
               AND oi.order_id = $2
               AND o.id = $2
             RETURNING
                 o.id AS order_id,
                 o.order_number,
                 oi.id AS item_id,
                 oi.qr_scan_count,
                 oi.last_qr_scanned_at`,
            [request.params.itemId, request.params.orderId],
        );

        if (result.rowCount !== 1) {
            return response.status(404).json({
                error: "QR kod je nevažeći ili tepih više ne postoji u ovoj narudžbi.",
            });
        }

        const scan = result.rows[0];
        await writeAuditLog({
            userId: request.user.id,
            username: request.user.username,
            role: request.user.role,
            action: "QR_SCAN",
            method: request.method,
            pathName: request.originalUrl,
            statusCode: 200,
            details: {
                orderId: scan.order_id,
                orderCode: `N${Number(scan.order_number)}`,
                itemId: scan.item_id,
                scanCount: Number(scan.qr_scan_count),
            },
        });

        return response.json({
            orderId: scan.order_id,
            orderCode: `N${Number(scan.order_number)}`,
            itemId: scan.item_id,
            scanCount: Number(scan.qr_scan_count),
            lastScannedAt: scan.last_qr_scanned_at,
        });
    } catch (error) {
        return next(error);
    }
});


app.get("/api/orders", authenticate, requirePermission("orders.view"), async (request, response, next) => {
    try {
        const search = String(request.query.search || "").trim();
        const dateFrom = String(request.query.dateFrom || "").trim();
        const dateTo = String(request.query.dateTo || "").trim();
        const values = [];
        const conditions = [];

        if (search) {
            values.push(`%${search}%`);
            conditions.push(`(
                CAST(o.order_number AS TEXT) ILIKE $${values.length}
                OR c.first_name ILIKE $${values.length}
                OR c.last_name ILIKE $${values.length}
                OR c.company_name ILIKE $${values.length}
                OR c.phone ILIKE $${values.length}
                OR c.address ILIKE $${values.length}
            )`);
        }

        if (dateFrom) {
            values.push(dateFrom);
            conditions.push(`o.order_date >= $${values.length}::date`);
        }

        if (dateTo) {
            values.push(dateTo);
            conditions.push(`o.order_date <= $${values.length}::date`);
        }

        const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

        const result = await pool.query(
            `SELECT o.id, o.order_number, o.customer_id,
                    CONCAT_WS(' ', c.first_name, c.last_name) AS customer_name,
                    c.phone, c.address, c.city, c.latitude, c.longitude,
                    o.order_date, o.status, o.note, o.delivery_price,
                    i.id AS invoice_id, i.invoice_no, i.status AS invoice_status,
                    i.payment_method AS invoice_payment_method, i.issued_at AS invoice_issued_at, i.due_date AS invoice_due_date,
                    COALESCE((
                        SELECT SUM(oi.total)
                        FROM order_items oi
                        WHERE oi.order_id = o.id
                    ), 0) AS items_total,
                    o.created_at, o.updated_at
             FROM orders o
             JOIN customers c ON c.id = o.customer_id
             LEFT JOIN invoices i ON i.order_id = o.id
             ${where}
             ORDER BY o.order_date DESC, o.order_number DESC
             LIMIT 200`,
            values,
        );

        response.json({ orders: result.rows.map(publicOrder) });
    } catch (error) {
        next(error);
    }
});

app.get("/api/orders/:id", authenticate, requirePermission("orders.view"), async (request, response, next) => {
    try {
        const orderResult = await pool.query(
            `SELECT o.id, o.order_number, o.customer_id,
                    CONCAT_WS(' ', c.first_name, c.last_name) AS customer_name,
                    c.phone, c.address, c.city, c.latitude, c.longitude,
                    o.order_date, o.status, o.note, o.delivery_price,
                    i.id AS invoice_id, i.invoice_no, i.status AS invoice_status,
                    i.payment_method AS invoice_payment_method, i.issued_at AS invoice_issued_at, i.due_date AS invoice_due_date,
                    o.created_at, o.updated_at
             FROM orders o
             JOIN customers c ON c.id = o.customer_id
             LEFT JOIN invoices i ON i.order_id = o.id
             WHERE o.id = $1`,
            [request.params.id],
        );

        if (orderResult.rowCount !== 1) {
            return response.status(404).json({ error: "Narudžba nije pronađena." });
        }

        const itemsResult = await pool.query(
            `SELECT id, order_id, service_name, unit, length_m, width_m,
                    quantity, unit_price, area_m2, total, note,
                    qr_scan_count, last_qr_scanned_at
             FROM order_items
             WHERE order_id = $1
             ORDER BY created_at, id`,
            [request.params.id],
        );

        return response.json({
            order: publicOrder(orderResult.rows[0]),
            items: itemsResult.rows.map(publicOrderItem),
        });
    } catch (error) {
        return next(error);
    }
});

app.post("/api/orders", authenticate, requirePermission("orders.create"), async (request, response, next) => {
    try {
        const input = normalizeOrderInput(request.body);
        const validationError = validateOrderInput(input);
        if (validationError) return response.status(400).json({ error: validationError });

        const customerResult = await pool.query(
            "SELECT id FROM customers WHERE id = $1 AND is_active = TRUE",
            [input.customerId],
        );
        if (customerResult.rowCount !== 1) {
            return response.status(400).json({ error: "Kupac nije pronađen ili nije aktivan." });
        }

        const result = await pool.query(
            `INSERT INTO orders (customer_id, order_date, status, note, created_by)
             VALUES ($1, COALESCE(NULLIF($2, '')::date, CURRENT_DATE), $3, $4, $5)
             RETURNING id, order_number, customer_id, order_date, status, note, created_at, updated_at`,
            [input.customerId, input.orderDate, input.status, input.note, request.user.id],
        );

        const detail = await pool.query(
            `SELECT o.id, o.order_number, o.customer_id,
                    CONCAT_WS(' ', c.first_name, c.last_name) AS customer_name,
                    c.phone, c.address, c.city, c.latitude, c.longitude,
                    o.order_date, o.status, o.note, o.delivery_price,
                    i.id AS invoice_id, i.invoice_no, i.status AS invoice_status,
                    i.payment_method AS invoice_payment_method, i.issued_at AS invoice_issued_at, i.due_date AS invoice_due_date,
                    o.created_at, o.updated_at
             FROM orders o
             JOIN customers c ON c.id = o.customer_id
             LEFT JOIN invoices i ON i.order_id = o.id
             WHERE o.id = $1`,
            [result.rows[0].id],
        );

        return response.status(201).json({
            order: publicOrder(detail.rows[0]),
            items: [],
        });
    } catch (error) {
        next(error);
    }
});


app.post("/api/orders/:id/repeat", authenticate, requirePermission("orders.create"), async (request, response, next) => {
    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        const sourceResult = await client.query(
            `SELECT o.id, o.order_number, o.customer_id, o.note, o.delivery_price,
                    c.is_active
             FROM orders o
             JOIN customers c ON c.id = o.customer_id
             WHERE o.id = $1
             FOR UPDATE`,
            [request.params.id],
        );

        if (sourceResult.rowCount !== 1) {
            await client.query("ROLLBACK");
            return response.status(404).json({ error: "Narudžba nije pronađena." });
        }

        const source = sourceResult.rows[0];
        if (!source.is_active) {
            await client.query("ROLLBACK");
            return response.status(400).json({ error: "Kupac više nije aktivan." });
        }

        const itemsResult = await client.query(
            `SELECT service_name, unit, length_m, width_m, quantity,
                    unit_price, area_m2, total, note
             FROM order_items
             WHERE order_id = $1
             ORDER BY created_at, id`,
            [request.params.id],
        );

        const orderResult = await client.query(
            `INSERT INTO orders
                (customer_id, order_date, status, note, created_by, delivery_requested, delivery_price)
             VALUES ($1, CURRENT_DATE, 'RECEIVED', $2, $3, ($4 > 0), $4)
             RETURNING id, order_number`,
            [
                source.customer_id,
                source.note
                    ? `Ponovljena narudžba iz N${source.order_number}: ${source.note}`
                    : `Ponovljena narudžba iz N${source.order_number}`,
                request.user.id,
                Number(source.delivery_price || 0),
            ],
        );

        const newOrder = orderResult.rows[0];

        for (const item of itemsResult.rows) {
            await client.query(
                `INSERT INTO order_items
                    (order_id, service_name, unit, length_m, width_m, quantity,
                     unit_price, area_m2, total, note)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
                [
                    newOrder.id,
                    item.service_name,
                    item.unit,
                    item.length_m,
                    item.width_m,
                    item.quantity,
                    item.unit_price,
                    item.area_m2,
                    item.total,
                    item.note,
                ],
            );
        }

        await client.query("COMMIT");

        const detail = await pool.query(
            `SELECT o.id, o.order_number, o.customer_id,
                    CONCAT_WS(' ', c.first_name, c.last_name) AS customer_name,
                    c.phone, c.address, c.city, c.latitude, c.longitude,
                    o.order_date, o.status, o.note, o.delivery_price,
                    i.id AS invoice_id, i.invoice_no, i.status AS invoice_status,
                    i.payment_method AS invoice_payment_method, i.issued_at AS invoice_issued_at, i.due_date AS invoice_due_date,
                    o.created_at, o.updated_at
             FROM orders o
             JOIN customers c ON c.id = o.customer_id
             LEFT JOIN invoices i ON i.order_id = o.id
             WHERE o.id = $1`,
            [newOrder.id],
        );

        const copiedItems = await pool.query(
            `SELECT id, order_id, service_name, unit, length_m, width_m,
                    quantity, unit_price, area_m2, total, note,
                    qr_scan_count, last_qr_scanned_at
             FROM order_items
             WHERE order_id = $1
             ORDER BY created_at, id`,
            [newOrder.id],
        );

        return response.status(201).json({
            order: publicOrder(detail.rows[0]),
            items: copiedItems.rows.map(publicOrderItem),
            sourceOrderNumber: Number(source.order_number),
        });
    } catch (error) {
        try {
            await client.query("ROLLBACK");
        } catch {
            // Rollback can fail if the connection was already closed.
        }
        return next(error);
    } finally {
        client.release();
    }
});

app.put("/api/orders/:id", authenticate, requirePermission("orders.edit"), async (request, response, next) => {
    try {
        const input = normalizeOrderInput(request.body);
        const validationError = validateOrderInput(input);
        if (validationError) return response.status(400).json({ error: validationError });

        const customerResult = await pool.query(
            "SELECT id FROM customers WHERE id = $1 AND is_active = TRUE",
            [input.customerId],
        );
        if (customerResult.rowCount !== 1) {
            return response.status(400).json({ error: "Kupac nije pronađen ili nije aktivan." });
        }

        const result = await pool.query(
            `UPDATE orders
             SET customer_id = $1,
                 order_date = COALESCE(NULLIF($2, '')::date, order_date),
                 status = $3,
                 note = $4,
                 updated_at = NOW()
             WHERE id = $5
             RETURNING id`,
            [input.customerId, input.orderDate, input.status, input.note, request.params.id],
        );

        if (result.rowCount !== 1) {
            return response.status(404).json({ error: "Narudžba nije pronađena." });
        }

        const detail = await pool.query(
            `SELECT o.id, o.order_number, o.customer_id,
                    CONCAT_WS(' ', c.first_name, c.last_name) AS customer_name,
                    c.phone, c.address, c.city, c.latitude, c.longitude,
                    o.order_date, o.status, o.note, o.delivery_price,
                    i.id AS invoice_id, i.invoice_no, i.status AS invoice_status,
                    i.payment_method AS invoice_payment_method, i.issued_at AS invoice_issued_at, i.due_date AS invoice_due_date,
                    o.created_at, o.updated_at
             FROM orders o
             JOIN customers c ON c.id = o.customer_id
             LEFT JOIN invoices i ON i.order_id = o.id
             WHERE o.id = $1`,
            [request.params.id],
        );
        return response.json({ order: publicOrder(detail.rows[0]) });
    } catch (error) {
        next(error);
    }
});

app.patch("/api/orders/:id/delivery", authenticate, requirePermission("orders.edit"), async (request, response, next) => {
    try {
        const rawPrice = request.body?.price;
        const price = Number(rawPrice);

        if (!Number.isFinite(price) || price < 0 || price > 1000000) {
            return response.status(400).json({
                error: "Cijena dostave mora biti između 0 i 1.000.000 KM.",
            });
        }

        const roundedPrice = Number(price.toFixed(2));
        const result = await pool.query(
            `UPDATE orders
             SET delivery_price = $1,
                 delivery_requested = ($1 > 0),
                 updated_at = NOW()
             WHERE id = $2
             RETURNING id, delivery_price`,
            [roundedPrice, request.params.id],
        );

        if (result.rowCount !== 1) {
            return response.status(404).json({ error: "Narudžba nije pronađena." });
        }

        return response.json({
            orderId: result.rows[0].id,
            deliveryPrice: Number(result.rows[0].delivery_price),
        });
    } catch (error) {
        return next(error);
    }
});

app.delete("/api/orders/:id", authenticate, requirePermission("orders.delete"), async (request, response, next) => {
    try {
        const result = await pool.query(
            "DELETE FROM orders WHERE id = $1 RETURNING id",
            [request.params.id],
        );
        if (result.rowCount !== 1) {
            return response.status(404).json({ error: "Narudžba nije pronađena." });
        }
        return response.status(204).end();
    } catch (error) {
        next(error);
    }
});

app.post("/api/orders/:id/items", authenticate, requirePermission("orders.edit"), async (request, response, next) => {
    try {
        const input = normalizeOrderItemInput(request.body);
        const validationError = validateOrderItemInput(input);
        if (validationError) return response.status(400).json({ error: validationError });

        const orderResult = await pool.query("SELECT id FROM orders WHERE id = $1", [request.params.id]);
        if (orderResult.rowCount !== 1) {
            return response.status(404).json({ error: "Narudžba nije pronađena." });
        }

        const area = input.unit === "m2"
            ? Number((input.lengthM * input.widthM).toFixed(2))
            : null;
        const billableQuantity = input.unit === "m2" ? area : input.quantity;
        const total = Number((billableQuantity * input.unitPrice).toFixed(2));

        const result = await pool.query(
            `INSERT INTO order_items
                (order_id, service_name, unit, length_m, width_m, quantity, unit_price, area_m2, total, note)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING id, order_id, service_name, unit, length_m, width_m,
                       quantity, unit_price, area_m2, total, note`,
            [
                request.params.id, input.serviceName, input.unit, input.lengthM,
                input.widthM, input.quantity, input.unitPrice, area, total,
            ],
        );

        return response.status(201).json({ item: publicOrderItem(result.rows[0]) });
    } catch (error) {
        next(error);
    }
});

app.delete("/api/orders/:orderId/items/:itemId", authenticate, requirePermission("orders.edit"), async (request, response, next) => {
    try {
        const result = await pool.query(
            `DELETE FROM order_items
             WHERE id = $1 AND order_id = $2
             RETURNING id`,
            [request.params.itemId, request.params.orderId],
        );
        if (result.rowCount !== 1) {
            return response.status(404).json({ error: "Stavka narudžbe nije pronađena." });
        }
        return response.status(204).end();
    } catch (error) {
        next(error);
    }
});


app.get("/api/invoices", authenticate, requirePermission("invoices.view"), async (request, response, next) => {
    try {
        const search = String(request.query.search || "").trim();
        const values = [];
        let where = "";

        if (search) {
            values.push(`%${search}%`);
            where = `WHERE (
                CAST(o.order_number AS TEXT) ILIKE $1
                OR COALESCE(CAST(i.invoice_no AS TEXT), '') ILIKE $1
                OR c.first_name ILIKE $1
                OR c.last_name ILIKE $1
                OR c.company_name ILIKE $1
                OR c.phone ILIKE $1
            )`;
        }

        const result = await pool.query(
            `SELECT o.id, o.order_number, o.customer_id,
                    CONCAT_WS(' ', c.first_name, c.last_name) AS customer_name,
                    c.phone, c.address, c.city, c.latitude, c.longitude,
                    o.order_date, o.status, o.note, o.delivery_price,
                    i.id AS invoice_id, i.invoice_no, i.status AS invoice_status,
                    i.payment_method AS invoice_payment_method, i.issued_at AS invoice_issued_at, i.due_date AS invoice_due_date,
                    o.created_at, o.updated_at
             FROM orders o
             JOIN customers c ON c.id = o.customer_id
             LEFT JOIN invoices i ON i.order_id = o.id
             ${where}
             ORDER BY o.order_date DESC, o.order_number DESC
             LIMIT 200`,
            values,
        );

        return response.json({ invoices: result.rows.map(publicOrder) });
    } catch (error) {
        return next(error);
    }
});

app.post("/api/invoices", authenticate, requirePermission("invoices.create"), async (request, response, next) => {
    const client = await pool.connect();

    try {
        const orderId = String(request.body?.orderId || "").trim();
        const paymentMethod = String(request.body?.paymentMethod || "cash").trim().toLowerCase();
        const dueDate = request.body?.dueDate ? String(request.body.dueDate).trim() : null;

        if (!orderId) {
            return response.status(400).json({ error: "Narudžba nije navedena." });
        }
        if (!["cash", "card", "bank"].includes(paymentMethod)) {
            return response.status(400).json({ error: "Način plaćanja nije ispravan." });
        }
        if (paymentMethod === "bank" && !/^\d{4}-\d{2}-\d{2}$/.test(dueDate || "")) {
            return response.status(400).json({ error: "Za žiralno plaćanje unesite datum dospijeća." });
        }

        await client.query("BEGIN");

        const orderResult = await client.query(
            `SELECT o.id
             FROM orders o
             WHERE o.id = $1
             FOR UPDATE`,
            [orderId],
        );

        if (orderResult.rowCount !== 1) {
            await client.query("ROLLBACK");
            return response.status(404).json({ error: "Narudžba nije pronađena." });
        }

        const itemsResult = await client.query(
            `SELECT id FROM order_items WHERE order_id = $1 LIMIT 1`,
            [orderId],
        );

        if (itemsResult.rowCount !== 1) {
            await client.query("ROLLBACK");
            return response.status(400).json({ error: "Račun se ne može snimiti bez izmjerenih stavki." });
        }

        const existing = await client.query(
            `SELECT id, invoice_no, status, payment_method, issued_at, due_date
             FROM invoices
             WHERE order_id = $1
             FOR UPDATE`,
            [orderId],
        );

        if (existing.rowCount === 1) {
            await client.query("ROLLBACK");
            const invoice = existing.rows[0];

            if (invoice.status === "CANCELLED") {
                return response.status(409).json({ error: "Ovaj račun je storniran i ne može se ponovo fakturisati." });
            }

            return response.json({
                invoice: {
                    id: invoice.id,
                    invoiceNumber: Number(invoice.invoice_no),
                    status: invoice.status,
                    paymentMethod: invoice.payment_method,
                    issuedAt: invoice.issued_at,
                    dueDate: invoice.due_date,
                },
            });
        }

        const result = await client.query(
            `INSERT INTO invoices (order_id, status, payment_method, issued_at, due_date, created_by)
             VALUES ($1, 'INVOICED', $2, CURRENT_DATE, $4, $3)
             RETURNING id, invoice_no, status, payment_method, issued_at, due_date`,
            [orderId, paymentMethod, request.user.id, paymentMethod === "bank" ? dueDate : null],
        );

        await client.query("COMMIT");

        return response.status(201).json({
            invoice: {
                id: result.rows[0].id,
                invoiceNumber: Number(result.rows[0].invoice_no),
                status: result.rows[0].status,
                paymentMethod: result.rows[0].payment_method,
                issuedAt: result.rows[0].issued_at,
                dueDate: result.rows[0].due_date,
            },
        });
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        return next(error);
    } finally {
        client.release();
    }
});

app.patch("/api/invoices/:id/cancel", authenticate, requirePermission("invoices.edit"), async (request, response, next) => {
    try {
        const result = await pool.query(
            `UPDATE invoices
             SET status = 'CANCELLED',
                 cancelled_at = COALESCE(cancelled_at, NOW()),
                 updated_at = NOW()
             WHERE id = $1 AND status = 'INVOICED'
             RETURNING id, invoice_no, status`,
            [request.params.id],
        );

        if (result.rowCount !== 1) {
            return response.status(404).json({ error: "Račun nije pronađen ili je već storniran." });
        }

        return response.json({
            invoice: {
                id: result.rows[0].id,
                invoiceNumber: Number(result.rows[0].invoice_no),
                status: result.rows[0].status,
            },
        });
    } catch (error) {
        return next(error);
    }
});




const BACKUP_TABLES = [
    ["roles", "SELECT code, name, description, is_system, created_at, updated_at FROM roles ORDER BY code"],
    ["permissions", "SELECT code, name, module, created_at FROM permissions ORDER BY code"],
    ["role_permissions", "SELECT role_code, permission_code FROM role_permissions ORDER BY role_code, permission_code"],
    ["users", "SELECT id, username, first_name, last_name, role, is_active, created_at, updated_at FROM users ORDER BY username"],
    ["customers", "SELECT id, first_name, last_name, company_name, phone, whatsapp, address, city, note, latitude, longitude, is_active, created_at, updated_at FROM customers ORDER BY created_at, id"],
    ["orders", "SELECT id, order_number, customer_id, order_date, status, note, created_by, delivery_requested, delivery_price, created_at, updated_at FROM orders ORDER BY order_number"],
    ["order_items", "SELECT id, order_id, service_name, unit, length_m, width_m, quantity, unit_price, area_m2, total, note, qr_scan_count, last_qr_scanned_at, created_at, updated_at FROM order_items ORDER BY created_at, id"],
    ["price_list", "SELECT id, service_name, unit, price, is_active, sort_order, created_at, updated_at FROM price_list ORDER BY sort_order, service_name"],
    ["invoices", "SELECT id, order_id, invoice_no, status, payment_method, issued_at, cancelled_at, created_by, created_at, updated_at FROM invoices ORDER BY invoice_no"],
];

async function createBusinessBackup({ createdBy = null, automatic = false } = {}) {
    await fs.mkdir(BACKUP_DIR, { recursive: true });

    const data = {};
    for (const [name, query] of BACKUP_TABLES) {
        const result = await pool.query(query);
        data[name] = result.rows;
    }

    const payload = {
        format: "super-clean-business-backup",
        version: 1,
        createdAt: new Date().toISOString(),
        automatic,
        data,
    };

    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `super-clean-backup-${stamp}.json`;
    const filePath = path.join(BACKUP_DIR, filename);
    await fs.writeFile(filePath, JSON.stringify(payload, null, 2), "utf8");

    await pool.query(
        `INSERT INTO backup_records (filename, backup_type, file_size_bytes, created_by)
         VALUES ($1, $2, $3, $4)`,
        [filename, automatic ? "AUTOMATIC" : "MANUAL", Buffer.byteLength(JSON.stringify(payload), "utf8"), createdBy],
    );

    await removeOldBackups();
    return { filename, filePath, createdAt: payload.createdAt };
}

async function removeOldBackups() {
    const cutoff = Date.now() - BACKUP_RETENTION_DAYS * 86400000;
    const result = await pool.query(
        `SELECT id, filename, created_at
         FROM backup_records
         WHERE created_at < NOW() - ($1::int * INTERVAL '1 day')`,
        [BACKUP_RETENTION_DAYS],
    );

    for (const row of result.rows) {
        try {
            await fs.unlink(path.join(BACKUP_DIR, row.filename));
        } catch (error) {
            if (error.code !== "ENOENT") console.error("Brisanje starog backupa nije uspjelo:", error.message);
        }
        await pool.query("DELETE FROM backup_records WHERE id = $1", [row.id]);
    }

    const files = await fs.readdir(BACKUP_DIR).catch(() => []);
    for (const filename of files) {
        if (!filename.startsWith("super-clean-backup-") || !filename.endsWith(".json")) continue;
        const filePath = path.join(BACKUP_DIR, filename);
        const stat = await fs.stat(filePath).catch(() => null);
        if (stat && stat.mtimeMs < cutoff) {
            await fs.unlink(filePath).catch(() => {});
        }
    }
}

async function runAutomaticBackup() {
    try {
        const latest = await pool.query(
            `SELECT created_at
             FROM backup_records
             WHERE backup_type = 'AUTOMATIC'
             ORDER BY created_at DESC
             LIMIT 1`,
        );

        const last = latest.rows[0]?.created_at
            ? new Date(latest.rows[0].created_at).getTime()
            : 0;

        if (Date.now() - last >= 24 * 60 * 60 * 1000) {
            await createBusinessBackup({ automatic: true });
            console.log("Automatski dnevni backup je napravljen.");
        }
    } catch (error) {
        console.error("Automatski backup nije uspio:", error.message);
    }
}


function validateBusinessBackupPayload(payload) {
    if (!payload || payload.format !== "super-clean-business-backup" || Number(payload.version) !== 1) {
        throw new Error("Datoteka nije važeći Super Clean backup.");
    }

    const requiredTables = BACKUP_TABLES.map(([name]) => name);
    if (!payload.data || typeof payload.data !== "object") {
        throw new Error("Backup nema odjeljak sa podacima.");
    }

    for (const table of requiredTables) {
        if (!Array.isArray(payload.data[table])) {
            throw new Error(`Backup nema ispravan odjeljak: ${table}.`);
        }
    }

    return payload;
}

async function runSystemSelfTest() {
    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        const customer = await client.query(
            `INSERT INTO customers
                (first_name, last_name, phone, address, city, note)
             VALUES ('TEST', 'Super Clean', '000000', 'TEST adresa', 'Banja Luka', 'Automatski test — biće poništen')
             RETURNING id`,
        );

        const order = await client.query(
            `INSERT INTO orders
                (customer_id, order_date, note, delivery_price, delivery_requested)
             VALUES ($1, CURRENT_DATE, 'Automatski test — biće poništen', 10, TRUE)
             RETURNING id, order_number`,
            [customer.rows[0].id],
        );

        const item = await client.query(
            `INSERT INTO order_items
                (order_id, service_name, unit, length_m, width_m, quantity, unit_price, area_m2, total, note)
             VALUES ($1, 'Pranje tepiha', 'm2', 2, 3, 1, 5, 6, 30, 'Automatski test')
             RETURNING id`,
            [order.rows[0].id],
        );

        const invoice = await client.query(
            `INSERT INTO invoices
                (order_id, status, payment_method, issued_at, due_date)
             VALUES ($1, 'INVOICED', 'bank', CURRENT_DATE, CURRENT_DATE + 8)
             RETURNING id, invoice_no`,
            [order.rows[0].id],
        );

        const qrTarget = `http://test.local/?order=${encodeURIComponent(order.rows[0].id)}&item=${encodeURIComponent(item.rows[0].id)}`;
        const qrBuffer = await QRCode.toBuffer(qrTarget, {
            type: "png",
            width: 180,
            margin: 2,
            errorCorrectionLevel: "M",
        });

        if (!Buffer.isBuffer(qrBuffer) || qrBuffer.length === 0) {
            throw new Error("QR generisanje nije uspjelo.");
        }

        const totals = await client.query(
            `SELECT
                COALESCE(SUM(total), 0)::numeric(12,2) AS items_total,
                (SELECT delivery_price FROM orders WHERE id = $1)::numeric(12,2) AS delivery_price
             FROM order_items
             WHERE order_id = $1`,
            [order.rows[0].id],
        );

        const itemsTotal = Number(totals.rows[0].items_total);
        const deliveryPrice = Number(totals.rows[0].delivery_price);
        const total = Number((itemsTotal + deliveryPrice).toFixed(2));

        if (total !== 40) {
            throw new Error(`Test obračuna nije prošao: očekivano 40.00 KM, dobijeno ${total.toFixed(2)} KM.`);
        }

        await client.query("ROLLBACK");

        return {
            passed: true,
            checks: [
                "Kupac",
                "Narudžba i N-broj",
                "Mjerenje i obračun",
                "Dostava",
                "Račun i datum dospijeća",
                "QR generisanje",
                "Automatsko poništavanje testnih podataka",
            ],
            total: "40.00",
        };
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
    } finally {
        client.release();
    }
}

async function restoreBusinessBackup(payload) {
    validateBusinessBackupPayload(payload);

    const data = payload.data;
    const client = await pool.connect();

    const columns = {
        roles: ["code", "name", "description", "is_system", "created_at", "updated_at"],
        permissions: ["code", "name", "module", "created_at"],
        role_permissions: ["role_code", "permission_code"],
        users: ["id", "username", "first_name", "last_name", "role", "is_active", "created_at", "updated_at"],
        customers: ["id", "first_name", "last_name", "company_name", "phone", "whatsapp", "address", "city", "note", "latitude", "longitude", "is_active", "created_at", "updated_at"],
        orders: ["id", "order_number", "customer_id", "order_date", "status", "note", "created_by", "delivery_requested", "delivery_price", "created_at", "updated_at"],
        order_items: ["id", "order_id", "service_name", "unit", "length_m", "width_m", "quantity", "unit_price", "area_m2", "total", "note", "qr_scan_count", "last_qr_scanned_at", "created_at", "updated_at"],
        price_list: ["id", "service_name", "unit", "price", "is_active", "sort_order", "created_at", "updated_at"],
        invoices: ["id", "order_id", "invoice_no", "status", "payment_method", "issued_at", "due_date", "cancelled_at", "created_by", "created_at", "updated_at"],
    };

    const order = ["roles", "permissions", "role_permissions", "users", "customers", "orders", "order_items", "price_list", "invoices"];

    try {
        await client.query("BEGIN");

        await client.query(`
            TRUNCATE TABLE
                sessions, invoices, order_items, orders, customers,
                role_permissions, users, roles, permissions, price_list
            RESTART IDENTITY
        `);

        for (const table of order) {
            const rows = data[table] || [];
            if (!rows.length) continue;

            const tableColumns = columns[table];
            const quotedColumns = tableColumns.map((column) => `"${column}"`).join(", ");
            const placeholders = tableColumns.map((_, index) => `$${index + 1}`).join(", ");

            for (const row of rows) {
                const values = tableColumns.map((column) => {
                    if (table === "order_items" && column === "qr_scan_count") {
                        return row[column] == null ? 0 : row[column];
                    }
                    return row[column] === undefined ? null : row[column];
                });

                await client.query(
                    `INSERT INTO "${table}" (${quotedColumns}) VALUES (${placeholders})`,
                    values,
                );
            }
        }

        await client.query(`
            SELECT setval(
                pg_get_serial_sequence('orders', 'order_number'),
                GREATEST(COALESCE((SELECT MAX(order_number) FROM orders), 1), 1),
                true
            )
        `);
        await client.query(`
            SELECT setval(
                pg_get_serial_sequence('invoices', 'invoice_no'),
                GREATEST(COALESCE((SELECT MAX(invoice_no) FROM invoices), 1), 1),
                true
            )
        `);

        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
    } finally {
        client.release();
    }
}

app.get("/api/admin/system/status", authenticate, requireAdmin, async (request, response, next) => {
    try {
        const [backupResult, countsResult, issueResult] = await Promise.all([
            pool.query(
                `SELECT filename, backup_type, file_size_bytes, created_at
                 FROM backup_records
                 ORDER BY created_at DESC
                 LIMIT 10`,
            ),
            pool.query(
                `SELECT
                    (SELECT COUNT(*)::int FROM customers WHERE is_active = TRUE) AS customers,
                    (SELECT COUNT(*)::int FROM orders) AS orders,
                    (SELECT COUNT(*)::int FROM order_items) AS items,
                    (SELECT COUNT(*)::int FROM invoices) AS invoices`,
            ),
            pool.query(
                `SELECT
                    (SELECT COUNT(*)::int
                     FROM orders o
                     WHERE NOT EXISTS (SELECT 1 FROM order_items oi WHERE oi.order_id = o.id)
                       AND o.order_date >= CURRENT_DATE - INTERVAL '30 days') AS orders_without_measurement,
                    (SELECT COUNT(*)::int
                     FROM orders o
                     WHERE EXISTS (SELECT 1 FROM order_items oi WHERE oi.order_id = o.id)
                       AND NOT EXISTS (SELECT 1 FROM invoices i WHERE i.order_id = o.id)
                       AND o.order_date >= CURRENT_DATE - INTERVAL '30 days') AS measured_without_invoice,
                    (SELECT COUNT(*)::int
                     FROM price_list
                     WHERE is_active = TRUE AND price <= 0) AS prices_without_value`,
            ),
        ]);

        const lastBackup = backupResult.rows[0] || null;
        const backupAgeHours = lastBackup
            ? Math.floor((Date.now() - new Date(lastBackup.created_at).getTime()) / 3600000)
            : null;

        const issues = [
            {
                code: "orders_without_measurement",
                label: "Narudžbe bez mjerenja",
                count: Number(issueResult.rows[0].orders_without_measurement),
            },
            {
                code: "measured_without_invoice",
                label: "Mjerenja bez računa",
                count: Number(issueResult.rows[0].measured_without_invoice),
            },
            {
                code: "prices_without_value",
                label: "Aktivne cijene bez vrijednosti",
                count: Number(issueResult.rows[0].prices_without_value),
            },
        ].filter((issue) => issue.count > 0);

        if (backupAgeHours === null || backupAgeHours >= 36) {
            issues.push({
                code: "backup_old",
                label: backupAgeHours === null ? "Backup nije napravljen" : "Backup je stariji od 36 sati",
                count: 1,
            });
        }

        response.json({
            backups: backupResult.rows.map((row) => ({
                filename: row.filename,
                type: row.backup_type,
                sizeBytes: Number(row.file_size_bytes),
                createdAt: row.created_at,
            })),
            lastBackup,
            backupAgeHours,
            counts: {
                customers: Number(countsResult.rows[0].customers),
                orders: Number(countsResult.rows[0].orders),
                items: Number(countsResult.rows[0].items),
                invoices: Number(countsResult.rows[0].invoices),
            },
            issues,
        });
    } catch (error) {
        next(error);
    }
});

app.get("/api/admin/audit", authenticate, requireAdmin, async (request, response, next) => {
    try {
        const limit = Math.min(Math.max(Number(request.query.limit) || 50, 1), 200);
        const result = await pool.query(
            `SELECT id, username, role, action, method, path, status_code, details, created_at
             FROM audit_logs
             ORDER BY created_at DESC
             LIMIT $1`,
            [limit],
        );

        response.json({
            logs: result.rows.map((row) => ({
                id: row.id,
                username: row.username,
                role: row.role,
                action: row.action,
                method: row.method,
                path: row.path,
                statusCode: row.status_code,
                details: row.details || {},
                createdAt: row.created_at,
            })),
        });
    } catch (error) {
        next(error);
    }
});

app.post("/api/admin/backup", authenticate, requireAdmin, async (request, response, next) => {
    try {
        const backup = await createBusinessBackup({
            createdBy: request.user.id,
            automatic: false,
        });

        await writeAuditLog({
            userId: request.user.id,
            username: request.user.username,
            role: request.user.role,
            action: "Napravljen ručni backup",
            method: "POST",
            pathName: "/api/admin/backup",
            statusCode: 201,
            details: { filename: backup.filename },
        });

        response.status(201).json({
            filename: backup.filename,
            createdAt: backup.createdAt,
            downloadUrl: `/api/admin/backup/${encodeURIComponent(backup.filename)}`,
        });
    } catch (error) {
        next(error);
    }
});

app.get("/api/admin/backup/:filename", authenticate, requireAdmin, async (request, response, next) => {
    try {
        const filename = path.basename(String(request.params.filename || ""));
        const result = await pool.query(
            "SELECT filename FROM backup_records WHERE filename = $1 LIMIT 1",
            [filename],
        );

        if (result.rowCount !== 1) {
            return response.status(404).json({ error: "Backup nije pronađen." });
        }

        return response.download(path.join(BACKUP_DIR, filename), filename);
    } catch (error) {
        next(error);
    }
});


app.post("/api/admin/self-test", authenticate, requireAdmin, async (request, response, next) => {
    try {
        const result = await runSystemSelfTest();

        await writeAuditLog({
            userId: request.user.id,
            username: request.user.username,
            role: request.user.role,
            action: "Pokrenut sistemski test",
            method: "POST",
            pathName: "/api/admin/self-test",
            statusCode: 200,
            details: { checks: result.checks, total: result.total },
        });

        response.json(result);
    } catch (error) {
        next(error);
    }
});

app.post(
    "/api/admin/backup/restore",
    authenticate,
    requireAdmin,
    express.text({ type: ["text/plain", "application/json"], limit: "10mb" }),
    async (request, response, next) => {
        try {
            let payload;
            try {
                payload = typeof request.body === "string" ? JSON.parse(request.body) : request.body;
            } catch {
                return response.status(400).json({ error: "Backup datoteka nije ispravan JSON." });
            }

            validateBusinessBackupPayload(payload);
            await restoreBusinessBackup(payload);

            await writeAuditLog({
                userId: request.user.id,
                username: request.user.username,
                role: request.user.role,
                action: "Vraćen backup",
                method: "POST",
                pathName: "/api/admin/backup/restore",
                statusCode: 200,
                details: { backupCreatedAt: payload.createdAt, backupVersion: payload.version },
            });

            response.json({
                restored: true,
                createdAt: payload.createdAt,
            });
        } catch (error) {
            next(error);
        }
    },
);

app.get("/api/dashboard/summary", authenticate, async (request, response, next) => {
    try {
        const result = await pool.query(
            `SELECT
                CURRENT_DATE::text AS current_date,
                (SELECT COUNT(*)::int FROM orders WHERE order_date = CURRENT_DATE) AS order_count,
                (SELECT COUNT(*)::int
                 FROM order_items oi
                 JOIN orders o ON o.id = oi.order_id
                 WHERE o.order_date = CURRENT_DATE) AS carpet_count,
                (SELECT COUNT(*)::int
                 FROM invoices
                 WHERE status = 'INVOICED' AND issued_at::date = CURRENT_DATE) AS invoiced_count,
                (SELECT COALESCE(SUM(CASE WHEN i.status = 'INVOICED'
                    THEN COALESCE(items.items_total, 0) + COALESCE(o.delivery_price, 0)
                    ELSE 0 END), 0)::numeric(12,2)
                 FROM invoices i
                 JOIN orders o ON o.id = i.order_id
                 LEFT JOIN LATERAL (
                    SELECT COALESCE(SUM(oi.total), 0) AS items_total
                    FROM order_items oi
                    WHERE oi.order_id = o.id
                 ) items ON TRUE
                 WHERE i.status = 'INVOICED' AND i.issued_at::date = CURRENT_DATE) AS invoiced_total,
                (SELECT COALESCE(SUM(delivery_price), 0)::numeric(12,2)
                 FROM orders WHERE order_date = CURRENT_DATE) AS delivery_total,
                (SELECT COUNT(*)::int
                 FROM customers
                 WHERE created_at::date = CURRENT_DATE) AS new_customer_count,
                (SELECT COUNT(*)::int
                 FROM orders o
                 WHERE NOT EXISTS (
                    SELECT 1 FROM order_items oi WHERE oi.order_id = o.id
                 ) AND o.order_date >= CURRENT_DATE - INTERVAL '30 days') AS orders_without_measurement,
                (SELECT COUNT(*)::int
                 FROM orders o
                 WHERE EXISTS (
                    SELECT 1 FROM order_items oi WHERE oi.order_id = o.id
                 ) AND NOT EXISTS (
                    SELECT 1 FROM invoices i WHERE i.order_id = o.id
                 ) AND o.order_date >= CURRENT_DATE - INTERVAL '30 days') AS measured_without_invoice,
                (SELECT COUNT(*)::int
                 FROM price_list
                 WHERE is_active = TRUE AND price <= 0) AS prices_without_value`,
        );

        const row = result.rows[0];
        const canViewOrders = await requestHasPermission(request, "orders.view");
        const canViewCustomers = await requestHasPermission(request, "customers.view");
        const canViewInvoices = await requestHasPermission(request, "invoices.view");
        const canViewPricing = await requestHasPermission(request, "pricing.view");

        const warnings = [];
        if (canViewOrders) {
            warnings.push({
                code: "orders_without_measurement",
                count: Number(row.orders_without_measurement),
                label: "Narudžbe bez mjerenja",
                description: "Narudžba još nema nijedan izmjereni tepih.",
                page: "orders",
            });
            if (canViewInvoices) {
                warnings.push({
                    code: "measured_without_invoice",
                    count: Number(row.measured_without_invoice),
                    label: "Mjerenje bez računa",
                    description: "Narudžba ima mjerenje, ali račun još nije napravljen.",
                    page: "orders",
                });
            }
        }
        if (canViewPricing) {
            warnings.push({
                code: "prices_without_value",
                count: Number(row.prices_without_value),
                label: "Cijene bez vrijednosti",
                description: "Aktivne usluge u cjenovniku imaju cijenu 0 KM.",
                page: "pricing",
            });
        }

        return response.json({
            date: row.current_date,
            summary: {
                orderCount: canViewOrders ? Number(row.order_count) : null,
                carpetCount: canViewOrders ? Number(row.carpet_count) : null,
                invoicedCount: canViewInvoices ? Number(row.invoiced_count) : null,
                invoicedTotal: canViewInvoices ? Number(row.invoiced_total) : null,
                deliveryTotal: canViewOrders ? Number(row.delivery_total) : null,
                newCustomerCount: canViewCustomers ? Number(row.new_customer_count) : null,
            },
            warnings: warnings.filter((warning) => warning.count > 0),
        });
    } catch (error) {
        return next(error);
    }
});

app.get("/api/search", authenticate, async (request, response, next) => {
    try {
        const query = String(request.query.q || "").trim();
        if (query.length < 2) {
            return response.json({ results: [] });
        }

        const pattern = `%${query.replaceAll("%", "\\%").replaceAll("_", "\\_")}%`;
        const results = [];

        if (await requestHasPermission(request, "orders.view")) {
            const orders = await pool.query(
                `SELECT o.id, o.order_number, o.order_date,
                        COALESCE(NULLIF(TRIM(CONCAT_WS(' ', c.first_name, c.last_name)), ''), c.company_name, 'Bez kupca') AS customer_name,
                        c.phone
                 FROM orders o
                 JOIN customers c ON c.id = o.customer_id
                 WHERE CAST(o.order_number AS TEXT) ILIKE $1
                    OR COALESCE(c.first_name, '') ILIKE $1
                    OR COALESCE(c.last_name, '') ILIKE $1
                    OR COALESCE(c.company_name, '') ILIKE $1
                    OR COALESCE(c.phone, '') ILIKE $1
                    OR COALESCE(c.address, '') ILIKE $1
                 ORDER BY o.order_date DESC, o.order_number DESC
                 LIMIT 8`,
                [pattern],
            );

            for (const row of orders.rows) {
                results.push({
                    type: "order",
                    id: row.id,
                    title: `N${row.order_number}`,
                    subtitle: `${row.customer_name} · ${row.phone || "bez telefona"} · ${formatDateForSearch(row.order_date)}`,
                });
            }
        }

        if (await requestHasPermission(request, "customers.view")) {
            const customers = await pool.query(
                `SELECT id,
                        COALESCE(NULLIF(TRIM(CONCAT_WS(' ', first_name, last_name)), ''), company_name, 'Bez naziva') AS customer_name,
                        phone, address
                 FROM customers
                 WHERE COALESCE(first_name, '') ILIKE $1
                    OR COALESCE(last_name, '') ILIKE $1
                    OR COALESCE(company_name, '') ILIKE $1
                    OR COALESCE(phone, '') ILIKE $1
                    OR COALESCE(address, '') ILIKE $1
                 ORDER BY first_name, last_name
                 LIMIT 8`,
                [pattern],
            );

            for (const row of customers.rows) {
                results.push({
                    type: "customer",
                    id: row.id,
                    title: row.customer_name,
                    subtitle: `${row.phone || "bez telefona"}${row.address ? ` · ${row.address}` : ""}`,
                });
            }
        }

        if (await requestHasPermission(request, "invoices.view")) {
            const invoices = await pool.query(
                `SELECT i.id, i.order_id, i.invoice_no, i.status, o.order_number,
                        COALESCE(NULLIF(TRIM(CONCAT_WS(' ', c.first_name, c.last_name)), ''), c.company_name, 'Bez kupca') AS customer_name
                 FROM invoices i
                 JOIN orders o ON o.id = i.order_id
                 JOIN customers c ON c.id = o.customer_id
                 WHERE CAST(i.invoice_no AS TEXT) ILIKE $1
                    OR CAST(o.order_number AS TEXT) ILIKE $1
                    OR COALESCE(c.first_name, '') ILIKE $1
                    OR COALESCE(c.last_name, '') ILIKE $1
                    OR COALESCE(c.company_name, '') ILIKE $1
                    OR COALESCE(c.phone, '') ILIKE $1
                 ORDER BY i.created_at DESC
                 LIMIT 8`,
                [pattern],
            );

            for (const row of invoices.rows) {
                results.push({
                    type: "invoice",
                    id: row.order_id,
                    title: `Račun ${row.invoice_no}`,
                    subtitle: `N${row.order_number || ""} · ${row.customer_name} · ${row.status === "CANCELLED" ? "Storniran" : "Fakturisan"}`,
                });
            }
        }

        return response.json({ results: results.slice(0, 12) });
    } catch (error) {
        return next(error);
    }
});

async function requestHasPermission(request, permission) {
    if (request.user.role === "ADMIN") return true;
    const result = await pool.query(
        "SELECT 1 FROM role_permissions WHERE role_code = $1 AND permission_code = $2",
        [request.user.role, permission],
    );
    return result.rowCount === 1;
}

function formatDateForSearch(value) {
    if (!value) return "";
    return new Intl.DateTimeFormat("bs-BA", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
    }).format(new Date(value));
}

app.get("/api/reports/summary", authenticate, requirePermission("reports.view"), async (request, response, next) => {
    try {
        const from = String(request.query.from || "").trim();
        const to = String(request.query.to || "").trim();

        if (!/^\d{4}-\d{2}-\d{2}$/.test(from) || !/^\d{4}-\d{2}-\d{2}$/.test(to)) {
            return response.status(400).json({ error: "Period izvještaja nije ispravan." });
        }

        if (from > to) {
            return response.status(400).json({ error: "Početni datum ne može biti nakon završnog." });
        }

        const summaryResult = await pool.query(
            `SELECT
                COUNT(*) FILTER (WHERE i.status = 'INVOICED')::INT AS invoiced_count,
                COUNT(*) FILTER (WHERE i.status = 'CANCELLED')::INT AS cancelled_count,
                COALESCE(SUM(
                    CASE WHEN i.status = 'INVOICED'
                    THEN COALESCE(items.items_total, 0) + COALESCE(o.delivery_price, 0)
                    ELSE 0 END
                ), 0)::NUMERIC(12,2) AS invoiced_total,
                COALESCE(SUM(
                    CASE WHEN i.status = 'CANCELLED'
                    THEN COALESCE(items.items_total, 0) + COALESCE(o.delivery_price, 0)
                    ELSE 0 END
                ), 0)::NUMERIC(12,2) AS cancelled_total,
                COALESCE(SUM(
                    CASE WHEN i.status = 'INVOICED'
                    THEN COALESCE(items.item_count, 0)
                    ELSE 0 END
                ), 0)::INT AS carpet_count,
                COALESCE(SUM(
                    CASE WHEN i.status = 'INVOICED'
                    THEN COALESCE(o.delivery_price, 0)
                    ELSE 0 END
                ), 0)::NUMERIC(12,2) AS delivery_total
             FROM invoices i
             JOIN orders o ON o.id = i.order_id
             LEFT JOIN LATERAL (
                SELECT
                    COALESCE(SUM(oi.total), 0) AS items_total,
                    COUNT(oi.id)::INT AS item_count
                FROM order_items oi
                WHERE oi.order_id = o.id
             ) items ON TRUE
             WHERE i.issued_at BETWEEN $1::date AND $2::date`,
            [from, to],
        );

        const dailyResult = await pool.query(
            `SELECT
                i.issued_at::date AS report_date,
                COUNT(*) FILTER (WHERE i.status = 'INVOICED')::INT AS invoiced_count,
                COUNT(*) FILTER (WHERE i.status = 'CANCELLED')::INT AS cancelled_count,
                COALESCE(SUM(
                    CASE WHEN i.status = 'INVOICED'
                    THEN COALESCE(items.items_total, 0) + COALESCE(o.delivery_price, 0)
                    ELSE 0 END
                ), 0)::NUMERIC(12,2) AS invoiced_total,
                COALESCE(SUM(
                    CASE WHEN i.status = 'CANCELLED'
                    THEN COALESCE(items.items_total, 0) + COALESCE(o.delivery_price, 0)
                    ELSE 0 END
                ), 0)::NUMERIC(12,2) AS cancelled_total
             FROM invoices i
             JOIN orders o ON o.id = i.order_id
             LEFT JOIN LATERAL (
                SELECT COALESCE(SUM(oi.total), 0) AS items_total
                FROM order_items oi
                WHERE oi.order_id = o.id
             ) items ON TRUE
             WHERE i.issued_at BETWEEN $1::date AND $2::date
             GROUP BY i.issued_at::date
             ORDER BY report_date DESC`,
            [from, to],
        );

        return response.json({
            from,
            to,
            summary: summaryResult.rows[0],
            daily: dailyResult.rows,
        });
    } catch (error) {
        return next(error);
    }
});

app.get("/api/geocode", authenticate, requirePermission("customers.view"), async (request, response, next) => {
    try {
        const address = String(request.query.address || "").trim();
        const city = String(request.query.city || "").trim();
        if (address.length < 3) {
            return response.status(400).json({ error: "Unesi adresu prije pretrage." });
        }

        const query = [address, city || "Banja Luka", "Bosna i Hercegovina"]
            .filter(Boolean)
            .join(", ");

        const url = new URL("https://nominatim.openstreetmap.org/search");
        url.searchParams.set("format", "jsonv2");
        url.searchParams.set("limit", "5");
        url.searchParams.set("countrycodes", "ba");
        url.searchParams.set("q", query);

        const result = await fetch(url, {
            headers: {
                "User-Agent": "SuperClean-BanjaLuka/1.0",
                "Accept-Language": "bs,en",
            },
            signal: AbortSignal.timeout(8000),
        });

        if (!result.ok) {
            return response.status(502).json({
                error: "Servis za pronalaženje adrese trenutno nije dostupan.",
            });
        }

        const places = await result.json();
        return response.json({
            results: places.map((place) => ({
                latitude: Number(place.lat),
                longitude: Number(place.lon),
                displayName: place.display_name,
            })),
        });
    } catch (error) {
        if (error.name === "TimeoutError" || error.name === "AbortError") {
            return response.status(504).json({ error: "Pretraga adrese je istekla. Pokušaj ponovo." });
        }
        return next(error);
    }
});

app.get("/api/health", async (request, response, next) => {
    try {
        await pool.query("SELECT 1");
        response.json({ ok: true });
    } catch (error) {
        next(error);
    }

    if (request.path.startsWith("/api/")) {
        return next();
    }
app.get("/{*splat}", async (request, response, next) => { 
        const indexPath = path.join(__dirname, "public", "index.html");
        return response.send(await fs.readFile(indexPath, "utf8"));
    } catch (error) {
        return next(error);
    }
});

app.use((error, request, response, next) => {
    console.error(error);
    if (response.headersSent) {
        return next(error);
    }

    return response.status(500).json({
        error: "Došlo je do greške na serveru.",
    });
});

async function cleanupSessions() {
    await pool.query("DELETE FROM sessions WHERE expires_at <= NOW()");
}

async function ensureInvoiceDueDateColumn() {
    await pool.query(
        "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS due_date DATE"
    );
}

async function ensureQrScanColumns() {
    await pool.query(
        `ALTER TABLE order_items
         ADD COLUMN IF NOT EXISTS qr_scan_count INTEGER NOT NULL DEFAULT 0`,
    );
    await pool.query(
        `ALTER TABLE order_items
         ADD COLUMN IF NOT EXISTS last_qr_scanned_at TIMESTAMPTZ`,
    );
}

async function start() {
    await pool.query("SELECT 1");
    await ensureInvoiceDueDateColumn();
    await ensureQrScanColumns();
    await cleanupSessions();

    setInterval(() => {
        cleanupSessions().catch((error) => {
            console.error("Čišćenje sesija nije uspjelo:", error);
        });
    }, 60 * 60 * 1000).unref();

    setTimeout(() => {
        runAutomaticBackup();
    }, 5000).unref();

    setInterval(() => {
        runAutomaticBackup();
    }, 60 * 60 * 1000).unref();

    app.listen(PORT, () => {
        console.log(`Super Clean aplikacija radi na http://localhost:${PORT}`);
    });
}

start().catch((error) => {
    console.error("Aplikacija se nije mogla pokrenuti:", error);
    process.exit(1);
});
