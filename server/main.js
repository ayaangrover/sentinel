require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { createClient } = require("redis");
const Queue = require("bull");
const Joi = require("joi");
const crypto = require("crypto");

const {
  MONGO_URI,
  JWT_SECRET,
  REDIS_URL,
  ALLOWED_ORIGINS,
  SCREENSHOT_ENC_KEY,
  NODE_ENV,
  PORT = 3000,
} = process.env;

if (!MONGO_URI || !JWT_SECRET || !REDIS_URL || !ALLOWED_ORIGINS || !SCREENSHOT_ENC_KEY) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

function normalizeKey(keyStr) {
  const tryHex = Buffer.from(keyStr, "hex");
  if (tryHex.length === 32) return tryHex;
  try {
    const tryB64 = Buffer.from(keyStr, "base64");
    if (tryB64.length === 32) return tryB64;
  } catch {}
  const utf = Buffer.from(keyStr, "utf8");
  if (utf.length !== 32) {
    console.error("SCREENSHOT_ENC_KEY must be 32 bytes.");
    process.exit(1);
  }
  return utf;
}
const ENC_KEY = normalizeKey(SCREENSHOT_ENC_KEY);

const app = express();
app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

const allowedOrigins = ALLOWED_ORIGINS.split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    return allowedOrigins.includes(origin) ? cb(null, true) : cb(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: false
}));

const generalLimiter = rateLimit({ windowMs: 15000, max: 30 });
app.use(generalLimiter);
const writeLimiter = rateLimit({ windowMs: 15000, max: 10 });

mongoose.set("strictQuery", true);
mongoose.connect(MONGO_URI).then(() => {
  console.log("Connected to MongoDB");
}).catch(err => {
  console.error("MongoDB connection error:", err);
  process.exit(1);
});

function rejectDollarKeys(obj, path = "") {
  if (obj && typeof obj === "object") {
    if (Array.isArray(obj)) {
      obj.forEach((v, i) => rejectDollarKeys(v, `${path}[${i}]`));
    } else {
      for (const k of Object.keys(obj)) {
        if (k.startsWith("$")) {
          throw new Error(`Invalid key '${k}' at ${path || "root"}`);
        }
        rejectDollarKeys(obj[k], path ? `${path}.${k}` : k);
      }
    }
  }
}

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, index: true },
  passwordHash: String,
  role: { type: String, enum: ["admin", "student"], default: "student" },
  userId: { type: String, unique: true, index: true },
}, { timestamps: true, versionKey: false });
const User = mongoose.model("User", userSchema);

const ruleSchema = new mongoose.Schema({
  id: { type: Number, unique: true, required: true, index: true },
  condition: { type: mongoose.Schema.Types.Mixed, required: true },
  action: { type: mongoose.Schema.Types.Mixed, required: true },
}, { timestamps: true, versionKey: false, strict: true });
ruleSchema.pre("validate", function(next) {
  try {
    rejectDollarKeys(this.condition);
    rejectDollarKeys(this.action);
    next();
  } catch (e) {
    next(e);
  }
});
const Rule = mongoose.model("Rule", ruleSchema);

const historySchema = new mongoose.Schema({
  userId: { type: String, index: true },
  tabVisited: { type: String },
  timestamp: { type: Date, default: Date.now, index: true },
}, { versionKey: false });
historySchema.index({ timestamp: 1 }, { expireAfterSeconds: 2592000 });
const History = mongoose.model("History", historySchema);

const captureSchema = new mongoose.Schema({
  userId: { type: String, index: true },
  timestamp: { type: Date, default: Date.now, index: true },
  iv: Buffer,
  tag: Buffer,
  data: Buffer,
}, { versionKey: false });
captureSchema.index({ timestamp: 1 }, { expireAfterSeconds: 604800 });
const Capture = mongoose.model("Capture", captureSchema);

function signToken(user) {
  return jwt.sign({ sub: user.userId, role: user.role }, JWT_SECRET, { expiresIn: "12h" });
}

function authRequired(req, res, next) {
  const hdr = req.headers.authorization || "";
  const [, token] = hdr.split(" ");
  if (!token) return res.status(401).json({ error: "Missing bearer token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.auth = { userId: payload.sub, role: payload.role };
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.auth) return res.status(401).json({ error: "Unauthenticated" });
    if (!roles.includes(req.auth.role)) return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const createUserSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  role: Joi.string().valid("admin", "student").required(),
  userId: Joi.string().max(128).required(),
});

const trackSchema = Joi.object({
  tabVisited: Joi.string().max(1024).required(),
});

const captureSchemaJoi = Joi.object({
  screenshot: Joi.string().base64({ paddingRequired: false }).allow("").optional(),
  dataUrl: Joi.string().max(10485760).optional(),
  timestamp: Joi.date().optional(),
}).or("screenshot", "dataUrl").custom((v, helpers) => {
  const raw = v.dataUrl || v.screenshot || "";
  const approxBytes = Math.ceil(raw.length * 0.75);
  if (approxBytes > 5242880) return helpers.error("any.invalid", "Screenshot too large");
  return v;
});

function encryptScreenshot(buffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, tag, data: encrypted };
}

function parseBase64Input(input) {
  if (!input) return null;
  const m = input.match(/^data:.*;base64,(.*)$/);
  const b64 = m ? m[1] : input;
  return Buffer.from(b64, "base64");
}

const requestQueue = new Queue("requestQueue", REDIS_URL);

requestQueue.process(5, async (job) => {
  const { type, payload } = job.data;
  if (type === "track") {
    const { userId, tabVisited, at } = payload;
    await History.create({ userId, tabVisited, timestamp: at || new Date() });
    return { ok: true };
  }
  if (type === "capture") {
    const { userId, timestamp, screenshotBuffer } = payload;
    const enc = encryptScreenshot(screenshotBuffer);
    await Capture.create({ userId, timestamp: timestamp || new Date(), ...enc });
    return { ok: true };
  }
  throw new Error("Unknown job type");
});

app.get("/status", (req, res) => res.sendStatus(200));

app.post("/auth/login", writeLimiter, async (req, res) => {
  const { error, value } = loginSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.message });
  const { email, password } = value;
  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });
  const token = signToken(user);
  res.json({ token, user: { email: user.email, role: user.role, userId: user.userId } });
});

app.post("/admin/users", authRequired, requireRole("admin"), writeLimiter, async (req, res) => {
  const { error, value } = createUserSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.message });
  const { email, password, role, userId } = value;
  const passwordHash = await bcrypt.hash(password, 12);
  try {
    const created = await User.create({ email, passwordHash, role, userId });
    res.status(201).json({ userId: created.userId, role: created.role, email: created.email });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post("/track", authRequired, requireRole("student", "admin"), writeLimiter, async (req, res) => {
  const { error, value } = trackSchema.validate(req.body, { stripUnknown: true });
  if (error) return res.status(400).json({ error: error.message });
  const userId = req.auth.userId;
  const at = new Date();
  await requestQueue.add({ type: "track", payload: { userId, tabVisited: value.tabVisited, at } }, { attempts: 2, removeOnComplete: true, removeOnFail: true });
  res.status(202).json({ accepted: true, at });
});

app.post("/capture", authRequired, requireRole("student", "admin"), writeLimiter, async (req, res) => {
  const { error, value } = captureSchemaJoi.validate(req.body, { stripUnknown: true });
  if (error) return res.status(400).json({ error: error.message });
  const userId = req.auth.userId;
  const timestamp = value.timestamp ? new Date(value.timestamp) : new Date();
  const buffer = value.dataUrl ? parseBase64Input(value.dataUrl) : parseBase64Input(value.screenshot);
  if (!buffer || buffer.length === 0) return res.status(400).json({ error: "Invalid screenshot payload" });
  await requestQueue.add({ type: "capture", payload: { userId, timestamp, screenshotBuffer: buffer } }, { attempts: 2, removeOnComplete: true, removeOnFail: true });
  res.status(202).json({ accepted: true, timestamp });
});

app.get("/students", authRequired, requireRole("admin"), async (req, res) => {
  const since = new Date(Date.now() - 15000);
  const latest = await History.aggregate([
    { $sort: { userId: 1, timestamp: -1 } },
    { $group: { _id: "$userId", lastActivity: { $first: "$timestamp" }, currentTab: { $first: "$tabVisited" } } },
  ]);
  const students = latest.map(x => ({
    userId: x._id,
    currentTab: x.currentTab,
    lastActivity: x.lastActivity,
    online: x.lastActivity > since,
  }));
  res.json(students);
});

app.get("/rules", authRequired, requireRole("admin"), async (req, res) => {
  const rules = await Rule.find({}).lean();
  res.json(rules);
});

app.post("/rules", authRequired, requireRole("admin"), writeLimiter, async (req, res) => {
  const schema = Joi.array().items(Joi.object({
    id: Joi.number().integer().required(),
    condition: Joi.object().required(),
    action: Joi.object().required(),
  })).min(0).required();

  const { error, value } = schema.validate(req.body.rules);
  if (error) return res.status(400).json({ error: error.message });

  try {
    value.forEach(r => { rejectDollarKeys(r.condition); rejectDollarKeys(r.action); });

    const session = await mongoose.startSession();
    session.startTransaction();
    await Rule.deleteMany({}, { session });
    await Rule.insertMany(value, { session });
    await session.commitTransaction();
    session.endSession();

    res.send("Rules updated");
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get("/history", authRequired, requireRole("admin"), async (req, res) => {
  const userId = String(req.query.userId || "");
  if (!userId) return res.status(400).json({ error: "userId query parameter is required" });
  const items = await History.find({ userId }).sort({ timestamp: 1 }).lean();
  res.json(items);
});

app.get("/capture/latest", authRequired, requireRole("admin"), async (req, res) => {
  const userId = String(req.query.userId || "");
  if (!userId) return res.status(400).json({ error: "userId query parameter is required" });
  const latest = await Capture.findOne({ userId }).sort({ timestamp: -1 }).lean();
  if (!latest) return res.json(null);
  res.json({
    userId: latest.userId,
    timestamp: latest.timestamp,
    hasImage: true,
  });
});

app.delete("/admin/clear-ephemeral", authRequired, requireRole("admin"), async (req, res) => {
  await History.deleteMany({});
  await Capture.deleteMany({});
  res.status(200).send("Ephemeral entries cleared");
});

app.use((err, req, res, next) => {
  if (NODE_ENV !== "production") console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => console.log(`Secure server running on port ${PORT}`));