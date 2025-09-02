import express from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const app = express();
app.use(express.json());

// Read environment variables (Render injects these automatically)
const PORT = process.env.PORT || 3000;
const KORE_CLIENT_ID = process.env.CLIENT_ID;
const KORE_CLIENT_SECRET = process.env.CLIENT_SECRET;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";

// Simple timing-safe comparison
function safeEqual(a, b) {
  const ab = Buffer.from(a || "", "utf8");
  const bb = Buffer.from(b || "", "utf8");
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// Kore WebSDK will call this endpoint
app.post("/sts", (req, res) => {
  const { clientId, clientSecret, userIdentity } = req.body || {};

  if (!clientId || !clientSecret) {
    return res.status(400).json({ error: "clientId and clientSecret are required" });
  }
  if (!safeEqual(clientId, KORE_CLIENT_ID) || !safeEqual(clientSecret, KORE_CLIENT_SECRET)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = now + 3600; // 1 hour expiry

  const payload = {
    sub: userIdentity || clientId,
    clientId,
    iat: now,
    exp
  };

  try {
    const token = jwt.sign(payload, JWT_SECRET, { algorithm: "HS256" });
    return res.json({ jwt: token });
  } catch (e) {
    console.error("JWT signing error:", e);
    return res.status(500).json({ error: "Failed to sign token" });
  }
});

// Health check
app.get("/health", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`JWT Service running on port ${PORT}`);
});
