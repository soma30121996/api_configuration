const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const basicAuth = require("basic-auth");
const cors = require("cors");
const swaggerUi = require("swagger-ui-express");
const fs = require("fs");
const path = require("path");
const serverless = require("serverless-http");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());

// =====================
// SWAGGER SETUP (lazy load)
// =====================
app.use("/docs", swaggerUi.serve, (req, res, next) => {
  try {
    const swaggerPath = path.join(__dirname, "../swagger.json");
    const swaggerData = fs.readFileSync(swaggerPath, "utf8");
    const swaggerDocument = JSON.parse(swaggerData);
    return swaggerUi.setup(swaggerDocument)(req, res, next);
  } catch (err) {
    console.error("Swagger load error:", err.message);
    return res.status(500).json({ error: "Failed to load swagger.json" });
  }
});

// =====================
// CONFIG
// =====================
const API_KEY = "test-api-key";
const SECRET_KEY = "mysecretkey";
const STATIC_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTc2NDMxNzI3NiwiZXhwIjoxNzY0MzIwODc2fQ.8loE1C11xYsA7iXRmJE2CnrL08-NTYNJcCVo5D4m-kw";

const users = {
  admin: {
    username: "admin",
    passwordHash: bcrypt.hashSync("admin123", 10)
  }
};

const PROJECT_INFO = {
  project_name: "AI Hub",
  manager: "Gowtham",
  dev_team: [
    { name: "Mohammed Rishal", role: "Full stack Developer" },
    { name: "Richu", role: "Front Developer & Prompt Engineer" },
    { name: "Muneeb", role: "Full stack Developer" },
    { name: "Zaheer", role: "ML Engineer" },
    { name: "Harsh Vardhan", role: "AI/ML Engineer" },
    { name: "Afsal", role: "ML Engineer" },
    { name: "Gnanasekaran Perumal", role: "Back-end Developer" }
  ],
  testing_team: [
    {
      name: "Somashekar N",
      role: "Manual & Automation Test Engineer, Prompt Engineer"
    },
    { name: "Swathi", role: "Manual & Automation Test Engineer, Prompt Engineer" }
  ],
  description:
    "AI Hub on Neutrinos is a framework for integrating AI/ML into apps with NLP, GenAI, analytics, and automation.",
  features: [
    "Ready-to-use AI Models",
    "Custom Model Integration",
    "API-First AI as a Service",
    "Workflow Automation",
    "Scalability for Enterprises"
  ],
  modules: [
    "Dashboard",
    "Prediction",
    "Extraction",
    "Tokens",
    "Assistant",
    "Knowledge",
    "Audit Logs",
    "Deployment"
  ]
};

// =====================
// HELPERS
// =====================
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, SECRET_KEY);
  } catch {
    return null;
  }
}

// =====================
// MIDDLEWARE: Bearer Auth
// =====================
function bearerAuth(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(403).json({ detail: "Bearer token missing" });
  }

  const token = authHeader.split(" ")[1];

  if (token === STATIC_TOKEN) {
    req.user = { username: "admin" };
    return next();
  }

  const payload = verifyToken(token);
  if (!payload) return res.status(403).json({ detail: "Invalid Bearer token" });

  req.user = { username: payload.sub };
  next();
}

// =====================
// ROUTES
// =====================

// Public
app.get("/public", (req, res) => {
  res.json({
    auth: "none",
    message: "Publicly accessible AI Hub details",
    data: PROJECT_INFO
  });
});

// API Key Protected
app.get("/apikey-protected", (req, res) => {
  const apiKey = req.headers["x-api-key"];
  if (apiKey === API_KEY) {
    return res.json({
      auth: "api_key",
      message: "You accessed AI Hub data with an API Key",
      data: PROJECT_INFO
    });
  }
  res.status(403).json({ detail: "Invalid API Key" });
});

// Basic Auth
app.get("/basic-protected", (req, res) => {
  const credentials = basicAuth(req);
  if (!credentials || !users[credentials.name]) {
    return res.status(401).json({ detail: "Invalid Basic Auth credentials" });
  }

  const valid = bcrypt.compareSync(
    credentials.pass,
    users[credentials.name].passwordHash
  );

  if (!valid) return res.status(401).json({ detail: "Invalid Basic Auth credentials" });

  res.json({
    auth: "basic",
    user: credentials.name,
    message: `Hello ${credentials.name}, you accessed AI Hub data with Basic Auth`,
    data: PROJECT_INFO
  });
});

// OAuth2: Login → token
app.post("/token", (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  if (user && bcrypt.compareSync(password, user.passwordHash)) {
    const token = createToken({ sub: username });
    return res.json({ access_token: token, token_type: "bearer" });
  }

  res.status(401).json({ detail: "Invalid username or password" });
});

// OAuth2 Protected
app.get("/oauth2-protected", bearerAuth, (req, res) => {
  res.json({
    auth: "oauth2",
    user: req.user.username,
    message: "You accessed AI Hub data with OAuth2",
    data: PROJECT_INFO
  });
});

// Bearer Protected
app.get("/bearer-protected", bearerAuth, (req, res) => {
  res.json({
    auth: "bearer",
    user: req.user.username,
    message: "You accessed AI Hub data with Bearer token",
    data: PROJECT_INFO
  });
});

// =====================
// EXPORT FOR VERCEL
// =====================
module.exports = serverless(app);
