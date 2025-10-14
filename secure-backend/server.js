import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import { simpleWAF } from "./middleware/waf.js";
import authRoutes from "./routes/authRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import logRoutes from "./routes/logRoutes.js";
import { pool } from "./config/db.js";

dotenv.config();
const app = express();

// Middleware bảo mật
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(rateLimit({ windowMs: 60 * 1000, max: 50 }));
app.use(simpleWAF);

// Kiểm tra DB
pool.query("SELECT 1").then(() => console.log("✅ MySQL connected")).catch(console.error);

// Routes
app.use("/api", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/admin/logs", logRoutes);

// Start
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`✅ Backend chạy tại http://localhost:${PORT}`));
