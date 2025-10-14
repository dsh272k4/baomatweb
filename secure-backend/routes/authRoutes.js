import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { pool } from "../config/db.js";

const router = express.Router();

// Đăng ký
router.post("/register", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ message: "Thiếu thông tin" });

        const [exists] = await pool.query("SELECT * FROM users WHERE username = ?", [username]);
        if (exists.length) return res.status(400).json({ message: "User đã tồn tại" });

        const hash = await bcrypt.hash(password, 10);
        await pool.query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')", [username, hash]);

        res.json({ message: "Đăng ký thành công" });
    } catch (err) {
        res.status(500).json({ message: "Lỗi server" });
    }
});

// Đăng nhập
router.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [username]);
    const user = rows[0];
    if (!user) return res.status(400).json({ message: "Sai tài khoản" });
    if (user.is_locked) return res.status(403).json({ message: "Tài khoản đã bị khóa" });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ message: "Sai mật khẩu" });

    const token = jwt.sign({ id: user.id, username, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Đăng nhập thành công", token });
});

export default router;
