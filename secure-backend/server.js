import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";

import { pool } from "./config/db.js";
import { simpleWAF } from "./middleware/waf.js";
import { checkPasswordExpiry } from "./middleware/passwordPolicy.js";
import { verifyToken } from "./middleware/auth.js";
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

// Thêm middleware kiểm tra hết hạn mật khẩu cho các route cần auth
app.use("/api", verifyToken, checkPasswordExpiry);

// health
app.get("/health", (req, res) => res.json({ status: "ok", time: new Date().toISOString() }));

// ensure default admin exists (optional)
import bcrypt from "bcrypt";
async function ensureAdmin() {
    try {
        const [rows] = await pool.query("SELECT id FROM users WHERE role='admin' LIMIT 1");
        if (rows.length === 0) {
            // Sử dụng mật khẩu mạnh mặc định
            const strongPassword = process.env.DEFAULT_ADMIN_PASSWORD || "Admin@Secure123!";
            const hash = await bcrypt.hash(strongPassword, 12);
            const now = new Date();

            await pool.query(
                "INSERT INTO users (username, password_hash, role, is_locked, created_at, password_changed_at) VALUES (?, ?, 'admin', 0, NOW(), ?)",
                ["admin", hash, now]
            );
            console.log("✅ Default admin created (username: admin)");
            console.log("⚠️  Please change the default admin password immediately!");
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