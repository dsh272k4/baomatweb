import express from "express";
import fs from "fs";
import path from "path";
import { verifyToken, requireAdmin } from "../middleware/auth.js";

const router = express.Router();

router.get("/", verifyToken, requireAdmin, (req, res) => {
    const wafLog = fs.readFileSync(path.resolve("logs", "waf.log"), "utf-8");
    const adminLog = fs.readFileSync(path.resolve("logs", "admin.log"), "utf-8");
    res.json({ wafLog, adminLog });
});

export default router;
