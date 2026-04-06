import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { pool } from "./db";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);


console.log("GHL location:", process.env.GHL_LOCATION_ID);
console.log("GHL token loaded:", !!process.env.GHL_API_KEY);
app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────

interface JwtPayload {
  userId: string;
  email: string;
  role: string;
}

interface AuthRequest extends Request {
  user?: JwtPayload;
}

// ─────────────────────────────────────────────
// MIDDLEWARE — requireAuth(roles[])
// Verifies JWT and optionally enforces role access.
// Usage:
//   requireAuth()              → any authenticated user
//   requireAuth(["wibiz_admin"]) → admin only
// ─────────────────────────────────────────────
function generateActivationToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function hashToken(token: string) {
  return bcrypt.hash(token, 10);
}

async function createActivationToken(userId: string) {
  const rawToken = generateActivationToken();
  const tokenHash = await hashToken(rawToken);

  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24); // 24 hours

  await pool.query(
    `INSERT INTO activation_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)`,
    [userId, tokenHash, expiresAt]
  );

  return {
    rawToken,
    expiresAt,
  };
}
function requireAuth(roles: string[] = []) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    try {
      const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET as string
      ) as JwtPayload;

      req.user = decoded;

      if (roles.length > 0 && !roles.includes(decoded.role)) {
        return res.status(403).json({ error: "Forbidden: insufficient role" });
      }

      return next();
    } catch {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  };
}




async function ghlRequest(path: string, options: RequestInit = {}) {
  const response = await fetch(`https://services.leadconnectorhq.com${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${process.env.GHL_API_KEY}`,
      Version: "2021-07-28",
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  const text = await response.text();
  let data: any = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!response.ok) {
    throw new Error(`GHL request failed: ${response.status} ${response.statusText} - ${JSON.stringify(data)}`);
  }

  return data;
}

async function addTagToContact(contactId: string, tag: string) {
  return ghlRequest(`/contacts/${contactId}/tags`, {
    method: "POST",
    body: JSON.stringify({
      tags: [tag],
    }),
  });
}

async function updateContactCustomFields(contactId: string, fields: any[]) {
  return ghlRequest(`/contacts/${contactId}`, {
    method: "PUT",
    body: JSON.stringify({
      customFields: fields,
    }),
  });
}

function normalizePlanTier(value: string | undefined | null): string | null {
  if (!value) return null;

  const v = String(value).trim().toLowerCase();

  if (["lite", "starter"].includes(v)) return "lite";
  if (["standard", "growth"].includes(v)) return "standard";
  if (["pro", "premium"].includes(v)) return "pro";

  return v || null;
}

function randomTempPassword(length = 16) {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
  let out = "";
  for (let i = 0; i < length; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}
async function issueActivationForUser(userId: string, email: string) {
  await pool.query(
    `DELETE FROM activation_tokens
     WHERE user_id = $1 AND used_at IS NULL`,
    [userId]
  );

  const { rawToken, expiresAt } = await createActivationToken(userId);

  const activationLink =
    `${process.env.FRONTEND_URL}/activate.html?token=${encodeURIComponent(rawToken)}&email=${encodeURIComponent(email)}`;

  console.log("ACTIVATION LINK:", activationLink);
  console.log("EXPIRES AT:", expiresAt.toISOString());

  return { activationLink, expiresAt };
}

async function upsertUserFromGhl(payload: {
  contactId: string;
  email: string;
  firstName?: string;
  lastName?: string;
  locationId?: string;
  planTier?: string | null;
  vertical?: string | null;
  hskdRequired?: boolean;
  sourceEvent: string;
  rawPayload: any;
}) {
  const {
    contactId,
    email,
    firstName,
    lastName,
    locationId,
    planTier,
    vertical,
    hskdRequired,
    sourceEvent,
    rawPayload,
  } = payload;

  const normalizedEmail = email.toLowerCase().trim();
  const finalPlanTier = normalizePlanTier(planTier);
  const finalLocationId = locationId || process.env.GHL_LOCATION_ID || null;

  if (!finalLocationId) {
    throw new Error("Missing location id for user sync");
  }

  const existing = await pool.query(
    `SELECT id, is_active, activated_at, password_hash
     FROM users
     WHERE ghl_contact_id = $1
     LIMIT 1`,
    [contactId]
  );

  let userId: string;
  let created = false;

  if (existing.rows.length === 0) {
    const result = await pool.query(
      `INSERT INTO users (
        email,
        password_hash,
        role,
        ghl_contact_id,
        ghl_location_id,
        plan_tier,
        vertical,
        hskd_required,
        first_name,
        last_name,
        is_active,
        activated_at,
        portal_status,
        created_at,
        updated_at
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),NOW())
      RETURNING id`,
      [
        normalizedEmail,
        null,                 // no password yet
        "client_admin",
        contactId,
        finalLocationId,
        finalPlanTier,
        vertical || null,
        hskdRequired ?? false,
        firstName || "",
        lastName || "",
        false,                // not active until activation
        null,                 // not activated yet
        "pending",            // requires portal_status column
      ]
    );

    userId = result.rows[0].id;
    created = true;
  } else {
    userId = existing.rows[0].id;

    await pool.query(
      `UPDATE users
       SET email = $1,
           first_name = $2,
           last_name = $3,
           ghl_location_id = $4,
           plan_tier = $5,
           vertical = $6,
           hskd_required = $7,
           updated_at = NOW()
       WHERE id = $8`,
      [
        normalizedEmail,
        firstName || "",
        lastName || "",
        finalLocationId,
        finalPlanTier,
        vertical || null,
        hskdRequired ?? false,
        userId,
      ]
    );
  }

  await pool.query(
    `INSERT INTO sync_events (
      entity_type,
      entity_id,
      event_type,
      payload_json,
      status
    )
    VALUES ($1,$2,$3,$4,$5)`,
    ["user", userId, sourceEvent, rawPayload, "success"]
  );

  return {
    userId,
    created,
  };
}

// ─────────────────────────────────────────────
// HEALTH
// ─────────────────────────────────────────────

app.get("/health", (_req: Request, res: Response) => {
  res.json({ ok: true });
});

// ─────────────────────────────────────────────
// WEBHOOK — GHL Provision
// Blueprint ref: Section 3 (Data Flow), Section 7 (Security)
// Access: Public (secret-validated)
// ─────────────────────────────────────────────

app.post("/api/webhooks/ghl/provision", async (req: Request, res: Response) => {
  let webhookLogId: string | null = null;

  try {
    const secret = req.header("x-wibiz-secret");
    if (!secret || secret !== process.env.GHL_WEBHOOK_SECRET) {
      return res.status(401).json({ error: "Invalid webhook secret" });
    }

    const {
      contact_id,
      email,
      first_name,
      last_name,
      plan_tier,
      vertical,
      hskd_required,
      location_id,
    } = req.body || {};

    if (!contact_id || !email) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const logResult = await pool.query(
      `INSERT INTO webhook_log (source, raw_payload, processed)
       VALUES ($1, $2, $3)
       RETURNING id`,
      ["ghl", req.body, false]
    );
    webhookLogId = logResult.rows[0].id;

    const result = await upsertUserFromGhl({
      contactId: contact_id,
      email,
      firstName: first_name,
      lastName: last_name,
      locationId: location_id,
      planTier: plan_tier,
      vertical: vertical || null,
      hskdRequired: hskd_required ?? false,
      sourceEvent: "ghl_provision_received",
      rawPayload: req.body,
    });

    await pool.query(
      `UPDATE webhook_log SET processed = true WHERE id = $1`,
      [webhookLogId]
    );

    return res.status(200).json({
      message: result.created ? "User created" : "User updated",
      userId: result.userId,
      created: result.created,
    });
  } catch (error) {
    console.error("Webhook error:", error);

    if (webhookLogId) {
      await pool.query(
        `UPDATE webhook_log SET error = $1 WHERE id = $2`,
        [String(error), webhookLogId]
      ).catch(() => {});
    }

    return res.status(500).json({ error: "Internal server error" });
  }
});

// ─────────────────────────────────────────────
// AUTH — Login
// Blueprint ref: Section 5 (Auth routes), Section 8 (Login Flow)
// Access: Public
// ─────────────────────────────────────────────

app.post("/api/auth/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const result = await pool.query(
      `SELECT * FROM users WHERE email = $1 LIMIT 1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];

   if (!user.is_active || user.portal_status === "pending") {
      return res.status(403).json({ error: "Account is not activated yet" });
    }

    if (!user.password_hash) {
      return res.status(403).json({ error: "Account is not activated yet" });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    await pool.query(
      `UPDATE users SET last_login_at = NOW() WHERE id = $1`,
      [user.id]
    );

    const jwtSecret = process.env.JWT_SECRET;

      if (!jwtSecret) {
        throw new Error("JWT_SECRET is not set");
      }

      const token = jwt.sign(
        { userId: user.id, email: user.email, role: user.role },
        jwtSecret,
        { expiresIn: "7d" }
      );

    return res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        role: user.role,
        plan_tier: user.plan_tier,
        vertical: user.vertical,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ─────────────────────────────────────────────
// AUTH — Get Current User
// Blueprint ref: Section 5 — GET /api/auth/me
// Access: Any authenticated user
// FIX: was /api/me — corrected to /api/auth/me per blueprint
// ─────────────────────────────────────────────

app.get("/api/auth/me", requireAuth(), async (req: AuthRequest, res: Response) => {
  try {
    const result = await pool.query(
      `SELECT id, email, first_name, last_name, role, plan_tier, vertical, hskd_required
       FROM users WHERE id = $1`,
      [req.user!.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.json(result.rows[0]);
  } catch (error) {
    console.error("Auth/me error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ─────────────────────────────────────────────
// AUTH — Change Password
// Blueprint ref: Section 5 — POST /api/auth/change-password
// Access: Any authenticated user
// ─────────────────────────────────────────────

app.post(
  "/api/auth/change-password",
  requireAuth(),
  async (req: AuthRequest, res: Response) => {
    try {
      const { current_password, new_password } = req.body || {};

      if (!current_password || !new_password) {
        return res
          .status(400)
          .json({ error: "current_password and new_password are required" });
      }

      if (new_password.length < 8) {
        return res
          .status(400)
          .json({ error: "new_password must be at least 8 characters" });
      }

      const result = await pool.query(
        `SELECT id, password_hash FROM users WHERE id = $1`,
        [req.user!.userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      const user = result.rows[0];

      const isMatch = await bcrypt.compare(current_password, user.password_hash);
      if (!isMatch) {
        return res.status(401).json({ error: "Current password is incorrect" });
      }

      const newHash = await bcrypt.hash(new_password, 10);

      await pool.query(
        `UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`,
        [newHash, user.id]
      );

      await pool.query(
        `INSERT INTO sync_events (entity_type, entity_id, event_type, payload_json, status)
         VALUES ($1, $2, $3, $4, $5)`,
        ["user", user.id, "password_changed", {}, "success"]
      );

      return res.status(200).json({ message: "Password updated successfully" });
    } catch (error) {
      console.error("Change password error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ─────────────────────────────────────────────
// DASHBOARD — Current user info + placeholder modules
// Blueprint ref: Section 5 (Dashboard routes), Section 11 (Success Criteria #7)
// Access: Any authenticated user
// ─────────────────────────────────────────────

app.get(
  "/api/dashboard",
  requireAuth(),
  async (req: AuthRequest, res: Response) => {
    try {
      const result = await pool.query(
        `SELECT id, email, first_name, last_name, role, plan_tier, vertical,
                hskd_required, activated_at, last_login_at
         FROM users WHERE id = $1`,
        [req.user!.userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      const user = result.rows[0];

      // Phase 1: placeholder modules — real content is Phase 2+
      const progressResult = await pool.query(
  `SELECT module_key, progress_percent, status, completed_at
   FROM module_progress
   WHERE user_id = $1`,
  [req.user!.userId]
);

const progressMap = new Map(
  progressResult.rows.map((row) => [row.module_key, row])
);

  const modules = [
    {
      id: "module-1",
      title: "Welcome to WiBiz Academy",
      status: progressMap.get("module-1")?.status || "available",
      progress: progressMap.get("module-1")?.progress_percent || 0,
      locked: (progressMap.get("module-1")?.status || "available") === "locked",
    },
    {
      id: "module-2",
      title: "Business Systems Foundations",
      status: progressMap.get("module-2")?.status || "locked",
      progress: progressMap.get("module-2")?.progress_percent || 0,
      locked: (progressMap.get("module-2")?.status || "locked") === "locked",
    },
    {
      id: "module-3",
      title: "GHL Mastery — Core Workflows",
      status: progressMap.get("module-3")?.status || "locked",
      progress: progressMap.get("module-3")?.progress_percent || 0,
      locked: (progressMap.get("module-3")?.status || "locked") === "locked",
    },
  ];

      return res.status(200).json({
        user: {
          id: user.id,
          email: user.email,
          first_name: user.first_name,
          last_name: user.last_name,
          role: user.role,
          plan_tier: user.plan_tier,
          vertical: user.vertical,
          hskd_required: user.hskd_required,
          activated_at: user.activated_at,
          last_login_at: user.last_login_at,
        },
        modules,
      });
    } catch (error) {
      console.error("Dashboard error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ─────────────────────────────────────────────
// ADMIN — List provisioned users
// Blueprint ref: Section 5 (Admin routes)
// Access: wibiz_admin only
// ─────────────────────────────────────────────

app.get(
  "/api/admin/users",
  requireAuth(["wibiz_admin"]),
  async (_req: AuthRequest, res: Response) => {
    try {
      const result = await pool.query(
        `SELECT id, email, first_name, last_name, role, plan_tier, vertical,
                ghl_contact_id, ghl_location_id, is_active, hskd_required,
                activated_at, last_login_at, created_at
         FROM users
         ORDER BY created_at DESC`
      );

      return res.status(200).json({
        total: result.rows.length,
        users: result.rows,
      });
    } catch (error) {
      console.error("Admin users error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ─────────────────────────────────────────────
// ADMIN — View sync events log
// Blueprint ref: Section 5 (Admin routes)
// Access: wibiz_admin only
// ─────────────────────────────────────────────

app.get(
  "/api/admin/sync-events",
  requireAuth(["wibiz_admin"]),
  async (req: AuthRequest, res: Response) => {
    try {
      // Optional filters via query params: ?entity_type=user&status=failed&limit=50
      const {
        entity_type,
        status,
        limit = "100",
        offset = "0",
      } = req.query as Record<string, string>;

      const conditions: string[] = [];
      const params: unknown[] = [];
      let paramIndex = 1;

      if (entity_type) {
        conditions.push(`entity_type = $${paramIndex++}`);
        params.push(entity_type);
      }
      if (status) {
        conditions.push(`status = $${paramIndex++}`);
        params.push(status);
      }

      const where =
        conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

      params.push(Number(limit));
      params.push(Number(offset));

      const result = await pool.query(
        `SELECT id, entity_type, entity_id, event_type, status,
                attempt_count, error_message, created_at, last_attempt_at
         FROM sync_events
         ${where}
         ORDER BY created_at DESC
         LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
        params
      );

      return res.status(200).json({
        total: result.rows.length,
        events: result.rows,
      });
    } catch (error) {
      console.error("Admin sync-events error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.get("/api/team", requireAuth(), async (req: AuthRequest, res: Response) => {
  try {
    const currentUser = await pool.query(
      `SELECT ghl_location_id FROM users WHERE id = $1`,
      [req.user!.userId]
    );

    const locationId = currentUser.rows[0].ghl_location_id;

    const result = await pool.query(
      `SELECT id, first_name, last_name, email, role, plan_tier
       FROM users
       WHERE ghl_location_id = $1
       AND is_active = true
       AND plan_tier IS NOT NULL
       AND TRIM(plan_tier) <> ''
       ORDER BY created_at DESC`,
      [locationId]
    );

    res.json({ members: result.rows });
  } catch (err) {
    console.error("Team error:", err);
    res.status(500).json({ error: "Failed to load team" });
  }
});

app.post("/api/progress/module-1/complete", requireAuth(), async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.userId;

    const result = await pool.query(
      `SELECT id, email, ghl_contact_id
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = result.rows[0];

    await pool.query("BEGIN");

    await pool.query(
      `INSERT INTO module_progress (user_id, module_key, progress_percent, status, completed_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW())
       ON CONFLICT (user_id, module_key)
       DO UPDATE SET
         progress_percent = EXCLUDED.progress_percent,
         status = EXCLUDED.status,
         completed_at = EXCLUDED.completed_at,
         updated_at = NOW()`,
      [user.id, "module-1", 100, "completed"]
    );

    await pool.query(
      `INSERT INTO module_progress (user_id, module_key, progress_percent, status, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (user_id, module_key)
       DO UPDATE SET
         status = EXCLUDED.status,
         updated_at = NOW()`,
      [user.id, "module-2", 0, "available"]
    );

    await pool.query(
      `INSERT INTO sync_events (
        entity_type,
        entity_id,
        event_type,
        payload_json,
        status
      )
      VALUES ($1, $2, $3, $4, $5)`,
      [
        "user",
        user.id,
        "module_1_completed",
        {
          module: "module-1",
          email: user.email,
          ghl_contact_id: user.ghl_contact_id || null
        },
        "success"
      ]
    );

  await pool.query("COMMIT");

  if (user.ghl_contact_id) {
    try {
      console.log("Tagging contact:", user.ghl_contact_id);
      await addTagToContact(user.ghl_contact_id, "module1_complete");

      await updateContactCustomFields(user.ghl_contact_id, [
        {
          key: "universe_module_1_status",
          value: "completed"
        },
        {
          key: "universe_last_completed_module",
          value: "module-1"
        },
        {
          key: "universe_progress_percent",
          value: 33
        }
      ]);
    } catch (err) {
      console.error("GHL sync error:", String(err));
    }
  }

    return res.status(200).json({
      message: "Module 1 completion recorded successfully",
      userId: user.id
    });
  } catch (error) {
    await pool.query("ROLLBACK").catch(() => {});
    console.error("Module 1 complete error:", error);
    return res.status(500).json({ error: "Failed to complete module 1" });
  }
});

app.post("/api/progress/module-2/complete", requireAuth(), async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.userId;

    const result = await pool.query(
      `SELECT id, email, ghl_contact_id
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = result.rows[0];

    await pool.query("BEGIN");

    await pool.query(
      `INSERT INTO module_progress (user_id, module_key, progress_percent, status, completed_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW())
       ON CONFLICT (user_id, module_key)
       DO UPDATE SET
         progress_percent = EXCLUDED.progress_percent,
         status = EXCLUDED.status,
         completed_at = EXCLUDED.completed_at,
         updated_at = NOW()`,
      [user.id, "module-2", 100, "completed"]
    );

    await pool.query(
      `INSERT INTO module_progress (user_id, module_key, progress_percent, status, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (user_id, module_key)
       DO UPDATE SET
         status = EXCLUDED.status,
         updated_at = NOW()`,
      [user.id, "module-3", 0, "available"]
    );

    await pool.query(
      `INSERT INTO sync_events (
        entity_type,
        entity_id,
        event_type,
        payload_json,
        status
      )
      VALUES ($1, $2, $3, $4, $5)`,
      [
        "user",
        user.id,
        "module_2_completed",
        {
          module: "module-2",
          email: user.email,
          ghl_contact_id: user.ghl_contact_id || null
        },
        "success"
      ]
    );

   await pool.query("COMMIT");

    if (user.ghl_contact_id) {
      try {
        console.log("MODULE 2 ROUTE HIT");
        console.log("Tagging contact:", user.ghl_contact_id);
        console.log("Adding tag: module2_complete");
        await addTagToContact(user.ghl_contact_id, "module2_complete");
        console.log("MODULE 2 CUSTOM FIELD SYNC VERSION LIVE");
        await updateContactCustomFields(user.ghl_contact_id, [
          {
            key: "universe_module_2_status",
            value: "completed"
          },
          {
            key: "universe_last_completed_module",
            value: "module-2"
          },
          {
            key: "universe_progress_percent",
            value: 67
          }
        ]);
      } catch (err) {
        console.error("GHL tag error:", err);
      }
    }

    return res.status(200).json({
      message: "Module 2 completion recorded successfully",
      userId: user.id
    });
  } catch (error) {
    await pool.query("ROLLBACK").catch(() => {});
    console.error("Module 2 complete error:", error);
    return res.status(500).json({ error: "Failed to complete module 2" });
  }
});
app.post("/api/progress/module-3/complete", requireAuth(), async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.userId;

    const result = await pool.query(
      `SELECT id, email, ghl_contact_id
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = result.rows[0];

    await pool.query("BEGIN");

    await pool.query(
      `INSERT INTO module_progress (user_id, module_key, progress_percent, status, completed_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW())
       ON CONFLICT (user_id, module_key)
       DO UPDATE SET
         progress_percent = EXCLUDED.progress_percent,
         status = EXCLUDED.status,
         completed_at = EXCLUDED.completed_at,
         updated_at = NOW()`,
      [user.id, "module-3", 100, "completed"]
    );

    await pool.query(
      `INSERT INTO sync_events (
        entity_type,
        entity_id,
        event_type,
        payload_json,
        status
      )
      VALUES ($1, $2, $3, $4, $5)`,
      [
        "user",
        user.id,
        "module_3_completed",
        {
          module: "module-3",
          email: user.email,
          ghl_contact_id: user.ghl_contact_id || null
        },
        "success"
      ]
    );

    await pool.query("COMMIT");

    if (user.ghl_contact_id) {
      try {
        console.log("MODULE 3 ROUTE HIT");
        console.log("Tagging contact:", user.ghl_contact_id);
        console.log("Adding tag: module3_complete");
        await addTagToContact(user.ghl_contact_id, "module3_complete");

        await updateContactCustomFields(user.ghl_contact_id, [
          {
            key: "universe_module_3_status",
            value: "completed"
          },
          {
            key: "universe_last_completed_module",
            value: "module-3"
          },
          {
            key: "universe_progress_percent",
            value: 100
          }
        ]);
      } catch (err) {
        console.error("GHL tag error:", err);
      }
    }

    return res.status(200).json({
      message: "Module 3 completion recorded successfully",
      userId: user.id
    });
  } catch (error) {
    await pool.query("ROLLBACK").catch(() => {});
    console.error("Module 3 complete error:", error);
    return res.status(500).json({ error: "Failed to complete module 3" });
  }
});
app.post("/api/webhooks/ghl/payment-success", async (req: Request, res: Response) => {
  try {
    const secret = req.header("x-wibiz-secret");
    if (!secret || secret !== process.env.GHL_WEBHOOK_SECRET) {
      return res.status(401).json({ error: "Invalid webhook secret" });
    }

    const {
      contactId,
      contact_id,
      email,
      firstName,
      first_name,
      lastName,
      last_name,
      locationId,
      location_id,
      planTier,
      plan_tier,
      vertical,
      hskdRequired,
      hskd_required,
    } = req.body || {};

    const finalContactId = contactId || contact_id;
    const finalFirstName = firstName || first_name;
    const finalLastName = lastName || last_name;
    const finalLocationId = locationId || location_id;
    const finalPlanTier = planTier || plan_tier;
    const finalHskdRequired = hskdRequired ?? hskd_required ?? false;

    if (!finalContactId || !email) {
      return res.status(400).json({ error: "contactId/contact_id and email are required" });
    }

    const result = await upsertUserFromGhl({
      contactId: finalContactId,
      email,
      firstName: finalFirstName,
      lastName: finalLastName,
      locationId: finalLocationId,
      planTier: finalPlanTier,
      vertical: vertical || null,
      hskdRequired: finalHskdRequired,
      sourceEvent: "ghl_payment_success",
      rawPayload: req.body,
    });

    const activation = await issueActivationForUser(
      result.userId,
      email
    );

    return res.status(200).json({
      message: result.created ? "User created from payment webhook" : "User updated from payment webhook",
      userId: result.userId,
      created: result.created,
    });
  } catch (error) {
    console.error("Payment webhook error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/auth/activate", async (req: Request, res: Response) => {
  try {
    const { email, token, password } = req.body || {};

    if (!email || !token || !password) {
      return res.status(400).json({ error: "email, token, and password are required" });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    const userResult = await pool.query(
      `SELECT id, email, is_active, portal_status
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [email.toLowerCase().trim()]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = userResult.rows[0];

    const tokenResult = await pool.query(
      `SELECT id, token_hash, expires_at, used_at
       FROM activation_tokens
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT 10`,
      [user.id]
    );

    if (tokenResult.rows.length === 0) {
      return res.status(400).json({ error: "No activation token found" });
    }

    let matchedToken: any = null;

    for (const row of tokenResult.rows) {
      if (row.used_at) continue;
      if (new Date(row.expires_at).getTime() < Date.now()) continue;

      const ok = await bcrypt.compare(token, row.token_hash);
      if (ok) {
        matchedToken = row;
        break;
      }
    }

    if (!matchedToken) {
      return res.status(400).json({ error: "Invalid or expired activation token" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    await pool.query("BEGIN");

    await pool.query(
      `UPDATE users
       SET password_hash = $1,
           is_active = true,
           portal_status = 'active',
           activated_at = NOW(),
           first_login_completed = true,
           updated_at = NOW()
       WHERE id = $2`,
      [passwordHash, user.id]
    );

    await pool.query(
      `UPDATE activation_tokens
       SET used_at = NOW()
       WHERE id = $1`,
      [matchedToken.id]
    );

    await pool.query(
      `INSERT INTO sync_events (
        entity_type,
        entity_id,
        event_type,
        payload_json,
        status
      )
      VALUES ($1,$2,$3,$4,$5)`,
      [
        "user",
        user.id,
        "account_activated",
        { email: user.email },
        "success"
      ]
    );

    await pool.query("COMMIT");

    return res.status(200).json({
      message: "Account activated successfully"
    });
  } catch (error) {
    await pool.query("ROLLBACK").catch(() => {});
    console.error("Activate error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/api/ghl/webhook", async (req, res) => {
  try {
    console.log("📩 GHL Webhook Received:", req.body);

    const payload = req.body;

    // Extract basic fields (we'll improve later)
    const contactId = payload.contact?.id;
    const email = payload.contact?.email;
    const firstName = payload.contact?.firstName;
    const lastName = payload.contact?.lastName;
    const locationId = payload.locationId;

    if (!contactId || !email) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const result = await upsertUserFromGhl({
      contactId,
      email,
      firstName,
      lastName,
      locationId,
      planTier: "lite", // temp (we improve later)
      vertical: null,
      hskdRequired: false,
      sourceEvent: "ghl_webhook",
      rawPayload: payload
    });

    console.log("✅ User synced:", result);

    res.json({ success: true });

  } catch (err) {
    console.error("❌ Webhook error:", err);
    res.status(500).json({ error: "Webhook failed" });
  }
});

// ─────────────────────────────────────────────
// SERVER START
// ─────────────────────────────────────────────

app.listen(PORT, async () => {
  console.log(`Server running on http://localhost:${PORT}`);

  try {
    const result = await pool.query("SELECT NOW()");
    console.log("DB connected:", result.rows[0]);
  } catch (err) {
    console.error("DB connection error:", err);
  }
});