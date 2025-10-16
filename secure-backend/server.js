// server.js
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";

import { pool } from "./config/db.js";
import { simpleWAF } from "./middleware/waf.js";
import authRoutes from "./routes/authRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import logRoutes from "./routes/logRoutes.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3001;

// ensure logs dir
const logDir = path.resolve("logs");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

// middlewares
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(rateLimit({ windowMs: 60 * 1000, max: 100 }));
app.use(simpleWAF);

// test DB
pool.query("SELECT 1").then(() => console.log("✅ MySQL connected")).catch((e) => console.error("MySQL connection error:", e));

// routes prefix /api
app.use("/api", authRoutes);
app.use("/api", adminRoutes);
app.use("/api", logRoutes);

// health
app.get("/health", (req, res) => res.json({ status: "ok", time: new Date().toISOString() }));

// ensure default admin exists (optional)
import bcrypt from "bcrypt";
async function ensureAdmin() {
    try {
        const [rows] = await pool.query("SELECT id FROM users WHERE role='admin' LIMIT 1");
        if (rows.length === 0) {
            const hash = await bcrypt.hash("Admin123", 10);
            await pool.query("INSERT INTO users (username, password_hash, role, is_locked, created_at) VALUES (?, ?, 'admin', 0, NOW())", ["admin", hash]);
            console.log("✅ Default admin created (username: admin, password: Admin123)");
        }
    } catch (err) {
        console.error("Ensure admin error:", err);
    }
}
ensureAdmin();

// start
app.listen(PORT, () => {
    console.log(`✅ Backend running on http://localhost:${PORT}`);
});
