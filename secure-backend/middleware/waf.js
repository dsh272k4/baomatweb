import fs from "fs";
import path from "path";

const wafLogPath = path.resolve("logs", "waf.log");

export function simpleWAF(req, res, next) {
    try {
        const bodyData = JSON.stringify(req.body || {});
        const queryData = JSON.stringify(req.query || {});
        const payload = (bodyData + queryData).toUpperCase();

        const malicious = ["DROP", "DELETE", "INSERT", "<SCRIPT>", "SELECT", "--", "OR 1=1"];
        const found = malicious.find(p => payload.includes(p));

        if (found) {
            const log = `[${new Date().toISOString()}] 🚫 WAF chặn yêu cầu: ${req.ip} - từ khóa: ${found}\n`;
            fs.appendFileSync(wafLogPath, log);
            return res.status(403).json({ message: "Yêu cầu bị chặn bởi WAF" });
        }

        next();
    } catch (err) {
        next();
    }
}
