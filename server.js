import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import rateLimit from "express-rate-limit";

const app = express();

// ✅ Required for Render/Heroku/behind load balancers
app.set("trust proxy", 1);

// --- CORS: allow ALL origins ---
app.use(cors()); // equivalent to origin: "*"

// --- Body parsers (SDK may send form-encoded) ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Rate limiting: 600 logins/min per IP ---
const limiter = rateLimit({
  windowMs: 60 * 1000,  // 1 minute
  max: 600,             // 600 requests per IP
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: { error: "Too many requests, please try again later." }
});
app.use(limiter);

// --- ENV VARS ---
// JWT_SECRET: Kore Client Secret
// JWT_ISSUER: Kore Client ID
// JWT_AUDIENCE: default Kore value (idproxy)
// JWT_EXPIRY: token lifetime in seconds
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me";
const JWT_ISSUER = process.env.JWT_ISSUER || "your-client-id";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "https://idproxy.kore.ai/authorize";
const JWT_EXPIRY = parseInt(process.env.JWT_EXPIRY || "3500", 10);

// --- Health check ---
app.get("/health", (_req, res) => res.json({ ok: true }));

// --- STS endpoint ---
app.post("/sts", (req, res) => {
  // SDK sends "identity" or "userId"
  const sub = req.body?.identity || req.body?.userId;

  if (typeof sub !== "string" || !sub || sub.length > 50) {
    return res.status(400).json({ error: "Invalid or missing user identity" });
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub,
    iss: JWT_ISSUER,
    aud: req.body?.aud || JWT_AUDIENCE,
    iat: now,
    exp: now + JWT_EXPIRY,
    isAnonymous: req.body?.isAnonymous === "true" || req.body?.isAnonymous === true
  };

  try {
    const token = jwt.sign(payload, JWT_SECRET, { algorithm: "HS256" });
    return res.json({ jwt: token }); // exact shape Kore expects
  } catch (err) {
    console.error("JWT signing error:", err);
    return res.status(500).json({ error: "Failed to sign token" });
  }
});

app.listen(PORT, () => {
  console.log(`JWT STS running on port ${PORT}`);
});
