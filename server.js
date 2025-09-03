import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import rateLimit from "express-rate-limit";

const app = express();

// --- CORS: lock to your WebSDK origins ---
app.use(cors({
  origin: [
    "https://southwire-cabletechsupport-dev.onrender.com",
    // "https://your-prod-origin.com",
  ]
}));

// --- Body parsers: JSON + x-www-form-urlencoded (jQuery $.ajax default) ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Rate limiting (10 req/min) ---
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later." }
});

// --- ENV VARS ---
// IMPORTANT: Best practice is to NOT send clientSecret from the browser.
// Sign with your Kore "Client Secret" kept only on the server (JWT_SECRET).
const PORT = process.env.PORT || 3000;

// HS256 signing key: use your Kore Client Secret here
const JWT_SECRET = process.env.JWT_SECRET || "change-me";

// iss should be your Kore Client ID
const JWT_ISSUER = process.env.JWT_ISSUER || "your-client-id";

// default audience per Kore docs (can be overridden by request 'aud')
const DEFAULT_AUD = process.env.JWT_AUDIENCE || "https://idproxy.kore.ai/authorize";

// token lifetime (seconds)
const JWT_EXPIRY = parseInt(process.env.JWT_EXPIRY || "3500", 10);

// Optional: validate incoming clientId/clientSecret from browser?
// Recommended: set VALIDATE_CLIENT_SECRET="false"
const VALIDATE_CLIENT_SECRET = (process.env.VALIDATE_CLIENT_SECRET || "false").toLowerCase() === "true";
const EXPECTED_CLIENT_ID = process.env.EXPECTED_CLIENT_ID || JWT_ISSUER;
const EXPECTED_CLIENT_SECRET = process.env.EXPECTED_CLIENT_SECRET || ""; // only used if VALIDATE_CLIENT_SECRET=true

// --- Health ---
app.get("/health", (_req, res) => res.json({ ok: true }));

// --- STS endpoint ---
app.post("/sts", limiter, (req, res) => {
  // The SDK example posts: clientId, clientSecret, identity, aud, isAnonymous
  const {
    clientId,
    clientSecret,
    identity,             // <- maps to sub
    userId,               // allow alternate field name
    aud,
    isAnonymous
  } = req.body || {};

  // Choose the identity field (SDK uses "identity")
  const sub = (typeof identity === "string" && identity) ||
              (typeof userId === "string" && userId) || "";

  if (!sub || sub.length > 50) {
    return res.status(400).json({ error: "Invalid or missing user identity" });
  }

  // Optional validation: (generally avoid sending clientSecret from the browser)
  if (VALIDATE_CLIENT_SECRET) {
    if (!clientId || clientId !== EXPECTED_CLIENT_ID ||
        !clientSecret || clientSecret !== EXPECTED_CLIENT_SECRET) {
      return res.status(401).json({ error: "Invalid client credentials" });
    }
  } else {
    // You may still sanity-check clientId if you want
    if (clientId && EXPECTED_CLIENT_ID && clientId !== EXPECTED_CLIENT_ID) {
      return res.status(401).json({ error: "Invalid clientId" });
    }
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    // Kore SDK claims
    sub,                       // subject = user identity
    iss: JWT_ISSUER,           // your Kore clientId
    aud: aud || DEFAULT_AUD,   // audience
    iat: now,
    exp: now + JWT_EXPIRY,
    isAnonymous: !!isAnonymous // passthrough if sent
  };

  try {
    const token = jwt.sign(payload, JWT_SECRET, { algorithm: "HS256" });
    return res.json({ jwt: token }); // exact shape the SDK expects
  } catch (err) {
    console.error("JWT signing error:", err);
    return res.status(500).json({ error: "Failed to sign token" });
  }
});

app.listen(PORT, () => {
  console.log(`JWT STS running on port ${PORT}`);
});
