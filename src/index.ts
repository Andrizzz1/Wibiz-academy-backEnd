import express, { Request, Response } from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import { pool } from "./db";
import jwt from "jsonwebtoken";
dotenv.config();

console.log("loaded env secret:", process.env.GHL_WEBHOOK_SECRET);
const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(cors());
app.use(express.json());

app.get("/health", (_req: Request, res: Response) => {
  res.json({ ok: true });
});

app.post("/api/webhooks/ghl/provision", async (req: Request, res: Response) => {
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
      temporary_pass,
      location_id,
    } = req.body || {};

    if (!contact_id || !email || !temporary_pass) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const passwordHash = await bcrypt.hash(temporary_pass, 10);

    await pool.query(
      `INSERT INTO webhook_log (source, raw_payload, processed)
       VALUES ($1, $2, $3)`,
      ["ghl", req.body, false]
    );

    const existing = await pool.query(
      `SELECT id FROM users WHERE ghl_contact_id = $1`,
      [contact_id]
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
      activated_at
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
    RETURNING id`,
    [
      email,
      passwordHash,
      "client_admin",
      contact_id,
      location_id,
      plan_tier,
      vertical,
      hskd_required ?? false,
      first_name,
      last_name,
    ]
  );

  userId = result.rows[0].id;
  created = true;
} else {
  userId = existing.rows[0].id;
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
      ["user", userId, "ghl_provision_received", req.body, "success"]
    );

    await pool.query(
      `UPDATE webhook_log
       SET processed = true
       WHERE id = (
         SELECT id FROM webhook_log
         ORDER BY received_at DESC
         LIMIT 1
       )`
    );

    return res.status(200).json({
        message: created ? "User created" : "User already exists",
        userId,
        created,
        });
  } catch (error) {
    console.error("Webhook error:", error);
    return res.status(500).json({
      error: "Internal server error",
    });
  }
});


app.post("/api/auth/login", async (req: Request, res: Response) => {
    console.log("login req.body:", req.body);
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

    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    await pool.query(
      `UPDATE users SET last_login_at = NOW() WHERE id = $1`,
      [user.id]
    );

    const token = jwt.sign(
    {
        userId: user.id,
        email: user.email,
        role: user.role,
    },
    process.env.JWT_SECRET as string,
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

app.get("/api/me", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as any;

    const result = await pool.query(
      `SELECT id, email, first_name, last_name, role, plan_tier, vertical
       FROM users WHERE id = $1`,
      [decoded.userId]
    );

    return res.json(result.rows[0]);
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
});
app.listen(PORT, async () => {
  console.log(`Server running on http://localhost:${PORT}`);

  try {
    const result = await pool.query("SELECT NOW()");
    console.log("DB connected:", result.rows[0]);
  } catch (err) {
    console.error("DB connection error:", err);
  }
});