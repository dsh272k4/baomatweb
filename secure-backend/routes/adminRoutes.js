// routes/adminRoutes.js
import express from "express";
import bcrypt from "bcrypt";
import fs from "fs";
import path from "path";
import { pool } from "../config/db.js";
import { verifyToken, requireAdmin } from "../middleware/auth.js";

const router = express.Router();
const logDir = path.resolve("logs");
const adminLogPath = path.join(logDir, "admin.log");

// Đảm bảo thư mục logs tồn tại
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
}

// ✅ Ghi log hành động admin
function logAdminAction(admin, action, target) {
    const logMsg = `[${new Date().toISOString()}] ${admin} -> ${action} user ${target}\n`;
    fs.appendFileSync(adminLogPath, logMsg);
}

// ✅ Lấy danh sách người dùng
router.get("/users", verifyToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query("SELECT id, username, role, is_locked, created_at FROM users");
        res.json(rows);
    } catch (err) {
        console.error("❌ Lỗi lấy danh sách user:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

// ✅ Thêm người dùng mới
router.post("/users", verifyToken, requireAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password)
        return res.status(400).json({ message: "Thiếu thông tin đăng ký" });

    try {
        const [exists] = await pool.query("SELECT id FROM users WHERE username=?", [username]);
        if (exists.length > 0) return res.status(400).json({ message: "Tên đăng nhập đã tồn tại" });

        const hash = bcrypt.hashSync(password, 10);
        await pool.query(
            "INSERT INTO users (username, password_hash, role, is_locked, created_at) VALUES (?, ?, ?, 0, NOW())",
            [username, hash, role || "user"]
        );

        logAdminAction(req.user.username, "Thêm", username);
        res.json({ message: "Thêm người dùng thành công" });
    } catch (err) {
        console.error("❌ Lỗi thêm user:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

// ✅ Cập nhật thông tin người dùng
router.put("/users/:id", verifyToken, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { username, role } = req.body;

    try {
        const [exists] = await pool.query(
            "SELECT id FROM users WHERE username = ? AND id != ?",
            [username, id]
        );
        if (exists.length > 0)
            return res.status(400).json({ message: "Tên đăng nhập đã tồn tại" });

        await pool.query("UPDATE users SET username=?, role=? WHERE id=?", [username, role, id]);

        logAdminAction(req.user.username, "Cập nhật", `ID ${id} (${username})`);
        res.json({ message: "Cập nhật người dùng thành công" });
    } catch (err) {
        console.error("❌ Lỗi cập nhật user:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

// ✅ Khóa / Mở khóa người dùng
router.put("/users/:id/lock", verifyToken, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { lock } = req.body;

    try {
        await pool.query("UPDATE users SET is_locked = ? WHERE id = ?", [lock ? 1 : 0, id]);
        logAdminAction(req.user.username, lock ? "Khóa" : "Mở khóa", `ID ${id}`);
        res.json({ message: "Cập nhật trạng thái người dùng thành công" });
    } catch (err) {
        console.error("❌ Lỗi khóa/mở user:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

// ✅ Xóa người dùng
router.delete("/users/:id", verifyToken, requireAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        const [user] = await pool.query("SELECT username FROM users WHERE id=?", [id]);
        if (user.length === 0) return res.status(404).json({ message: "Không tìm thấy user" });

        await pool.query("DELETE FROM users WHERE id=?", [id]);
        logAdminAction(req.user.username, "Xóa", `${user[0].username} (ID ${id})`);

        res.json({ message: "Đã xóa người dùng" });
    } catch (err) {
        console.error("❌ Lỗi xóa user:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});
// ✅ Đặt lại mật khẩu người dùng
router.put("/users/:id/reset-password", verifyToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { newPassword } = req.body;

  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ message: "Mật khẩu mới phải có ít nhất 6 ký tự" });
  }

  try {
    const [user] = await pool.query("SELECT username FROM users WHERE id = ?", [id]);
    if (user.length === 0) return res.status(404).json({ message: "Không tìm thấy user" });

    const hash = bcrypt.hashSync(newPassword, 10);
    await pool.query("UPDATE users SET password_hash=? WHERE id=?", [hash, id]);

    logAdminAction(req.user.username, "Reset mật khẩu", `${user[0].username} (ID ${id})`);
    res.json({ message: "Đặt lại mật khẩu thành công" });
  } catch (err) {
    console.error("❌ Lỗi đặt lại mật khẩu:", err);
    res.status(500).json({ message: "Lỗi máy chủ" });
  }
});


export default router;
