import bcrypt from "bcrypt";

// Chính sách mật khẩu
export const PASSWORD_POLICY = {
    minLength: 12,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    maxAgeDays: 90,
    passwordHistory: 5
};

// Kiểm tra độ mạnh mật khẩu
export function validatePasswordStrength(password) {
    const errors = [];

    if (password.length < PASSWORD_POLICY.minLength)
        errors.push(`Mật khẩu phải có ít nhất ${PASSWORD_POLICY.minLength} ký tự`);
    if (password.length > PASSWORD_POLICY.maxLength)
        errors.push(`Mật khẩu không được vượt quá ${PASSWORD_POLICY.maxLength} ký tự`);
    if (PASSWORD_POLICY.requireUppercase && !/[A-Z]/.test(password))
        errors.push("Mật khẩu phải chứa ít nhất một chữ cái in hoa");
    if (PASSWORD_POLICY.requireLowercase && !/[a-z]/.test(password))
        errors.push("Mật khẩu phải chứa ít nhất một chữ cái thường");
    if (PASSWORD_POLICY.requireNumbers && !/\d/.test(password))
        errors.push("Mật khẩu phải chứa ít nhất một số");
    if (PASSWORD_POLICY.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]/.test(password))
        errors.push("Mật khẩu phải chứa ít nhất một ký tự đặc biệt");

    const commonPasswords = ["Password123!", "Admin123!", "Welcome123!", "Changeme123!", "Aa@123456789"];
    if (commonPasswords.includes(password))
        errors.push("Mật khẩu quá phổ biến, vui lòng chọn mật khẩu khác");

    return { isValid: errors.length === 0, errors };
}

function safeJsonParse(str) {
    try {
        return JSON.parse(str);
    } catch {
        return [];
    }
}

// Kiểm tra mật khẩu trong lịch sử
export async function isPasswordInHistory(userId, newPassword, pool) {
    try {
        const [rows] = await pool.query("SELECT password_history FROM users WHERE id = ?", [userId]);
        if (!rows.length || !rows[0].password_history) return false;

        const historyData = rows[0].password_history;
        let passwordHistory = [];

        if (typeof historyData === "string") {
            if (historyData.startsWith("[")) passwordHistory = safeJsonParse(historyData);
            else passwordHistory = [historyData];
        } else if (Array.isArray(historyData)) passwordHistory = historyData;

        for (const oldHash of passwordHistory) {
            if (await bcrypt.compare(newPassword, oldHash)) return true;
        }

        return false;
    } catch (err) {
        console.error("Error checking password history:", err);
        return false;
    }
}

// Cập nhật lịch sử mật khẩu
export async function updatePasswordHistory(userId, newPasswordHash, pool) {
    try {
        const [rows] = await pool.query("SELECT password_history FROM users WHERE id = ?", [userId]);
        let history = [];

        if (rows.length && rows[0].password_history) {
            const data = rows[0].password_history;
            if (typeof data === "string") {
                if (data.startsWith("[")) history = safeJsonParse(data);
                else history = [data];
            } else if (Array.isArray(data)) history = data;
        }

        history.unshift(newPasswordHash);
        history = history.slice(0, PASSWORD_POLICY.passwordHistory);

        await pool.query("UPDATE users SET password_history = ? WHERE id = ?", [JSON.stringify(history), userId]);
    } catch (err) {
        console.error("Error updating password history:", err);
    }
}

// Kiểm tra hết hạn mật khẩu
export function isPasswordExpired(passwordChangedAt) {
    if (!passwordChangedAt) return false;
    const changed = new Date(passwordChangedAt);
    const expiry = new Date(changed.getTime() + PASSWORD_POLICY.maxAgeDays * 86400000);
    return new Date() > expiry;
}

// Middleware kiểm tra hết hạn mật khẩu
import { pool } from "../config/db.js";

export function checkPasswordExpiry(req, res, next) {
    if (!req.user) return next();
    if (req.path.includes("change-password") || req.path.includes("logout")) return next();

    pool.query("SELECT password_changed_at FROM users WHERE id = ?", [req.user.id])
        .then(([rows]) => {
            if (rows.length && isPasswordExpired(rows[0].password_changed_at)) {
                return res.status(403).json({
                    message: "Mật khẩu của bạn đã hết hạn. Vui lòng đổi mật khẩu để tiếp tục.",
                    code: "PASSWORD_EXPIRED",
                    redirectTo: "/profile"
                });
            }
            next();
        })
        .catch(err => {
            console.error("Error checking password expiry:", err);
            next();
        });
}
