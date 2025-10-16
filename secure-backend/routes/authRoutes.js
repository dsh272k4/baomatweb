import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { pool } from "../config/db.js";
import dotenv from "dotenv";

dotenv.config();
const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || "2h";

// REGISTER
router.post("/auth/register", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: "Vui lòng nhập đủ thông tin" });
        if (!/^[A-Za-z0-9_]{3,30}$/.test(username)) return res.status(400).json({ message: "Tên không hợp lệ" });
        if (password.length < 6) return res.status(400).json({ message: "Mật khẩu phải ≥ 6 ký tự" });

        const [exists] = await pool.query("SELECT id FROM users WHERE username=?", [username]);
        if (exists.length) return res.status(400).json({ message: "Tên người dùng đã tồn tại" });

        const hash = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (username, password_hash, role, failed_login_attempts, is_locked, created_at) VALUES (?, ?, 'user', 0, 0, NOW())",
            [username, hash]
        );


        res.status(201).json({ message: "Đăng ký thành công! Hãy đăng nhập." });
    } catch (err) {
        console.error("Register error:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

router.post("/auth/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: "Vui lòng nhập tên và mật khẩu" });

        const [rows] = await pool.query(
            "SELECT id, username, password_hash, role, failed_login_attempts, is_locked, lockout_until FROM users WHERE username=?",
            [username]
        );
        if (!rows.length) return res.status(401).json({ message: "Tài khoản hoặc mật khẩu sai" });

        const user = rows[0];
        const now = new Date();

        // 1️⃣ Kiểm tra khóa vĩnh viễn
        if (user.is_locked) return res.status(403).json({ message: "Tài khoản bị khóa bởi admin" });

        // 2️⃣ Kiểm tra khóa tạm thời
        if (user.lockout_until && now < user.lockout_until) {
            const remaining = Math.ceil((user.lockout_until - now) / 1000);
            return res.status(403).json({ message: `Tài khoản tạm khóa, thử lại sau ${remaining}s` });
        }

        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            // tăng số lần đăng nhập sai
            let attempts = user.failed_login_attempts + 1;
            let lockout = null;

            const lockSteps = [30, 60, 300, 900, 3600]; // 30s,1p,5p,15p,1h
            if (attempts >= 5) {
                const index = Math.min(attempts - 5, lockSteps.length - 1);
                lockout = new Date(now.getTime() + lockSteps[index] * 1000);
                attempts = 5; // giữ max 5 lần
            }

            await pool.query(
                "UPDATE users SET failed_login_attempts=?, lockout_until=? WHERE id=?",
                [attempts, lockout, user.id]
            );

            if (lockout) {
                const secs = Math.ceil((lockout - now) / 1000);
                return res.status(403).json({ message: `Tài khoản tạm khóa ${secs} giây` });
            }

            return res.status(401).json({ message: "Tài khoản hoặc mật khẩu sai" });
        }

        // đăng nhập thành công → reset fail count + lockout
        await pool.query(
            "UPDATE users SET failed_login_attempts=0, lockout_until=NULL WHERE id=?",
            [user.id]
        );

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES }
        );
        res.json({ token });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});
// GET current user
import { verifyToken } from "../middleware/auth.js";
router.get("/auth/me", verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.query("SELECT id, username, role FROM users WHERE id=?", [req.user.id]);
        res.json(rows[0]);
    } catch (err) {
        console.error("Get me error:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

export default router;
