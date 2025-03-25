require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");

const app = express();
app.use(express.json({ limit: "500mb" }));
app.use(express.urlencoded({ extended: true, limit: "500mb" }));

const allowedOrigins = [
  "https://ayaangrover.is-a.dev"
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
  }
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

const mongoURI = process.env["mongoURI"];
mongoose
  .connect(mongoURI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

let activeStudents = {};
let historyEntries = [];
let captureEntries = [];

const ruleSchema = new mongoose.Schema({
  id: Number,
  condition: Object,
  action: Object
});
const Rule = mongoose.model("Rule", ruleSchema);

app.post("/track", async (req, res) => {
  const { userId, tabVisited } = req.body;
  if (!userId || !tabVisited) return res.status(400).send("Missing parameters");
  
  activeStudents[userId] = {
    lastActivity: Date.now(),
    currentTab: tabVisited
  };
  
  historyEntries.push({
    userId,
    tabVisited,
    timestamp: Date.now()
  });
  
  res.send("Activity tracked");
  console.log("Activity tracked:", userId, tabVisited);
});

app.get("/students", (req, res) => {
  const now = Date.now();
  const students = Object.entries(activeStudents).map(([userId, data]) => ({
    userId,
    currentTab: data.currentTab,
    lastActivity: data.lastActivity,
    online: now - data.lastActivity < 15000
  }));
  res.json(students);
});

app.get("/rules", async (req, res) => {
  try {
    const rules = await Rule.find({});
    res.json(rules);
  } catch (error) {
    res.status(500).send("Error fetching rules");
  }
});

app.post("/rules", async (req, res) => {
  try {
    const newRules = req.body.rules;
    await Rule.deleteMany({});
    await Rule.insertMany(newRules);
    res.send("Rules updated");
  } catch (error) {
    res.status(500).send("Error updating rules");
  }
});

app.delete("/clear-entries", (req, res) => {
  activeStudents = {};
  res.status(200).send("Entries cleared");
});

app.get("/history", (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).send("userId query parameter is required");
  const userHistory = historyEntries.filter(entry => entry.userId === userId);
  res.json(userHistory);
});

app.post("/capture", (req, res) => {
  const { userId, screenshot, timestamp } = req.body;
  if (!userId || !screenshot || !timestamp) {
    return res.status(400).send("Missing parameters");
  }
  captureEntries.push({ userId, screenshot, timestamp });
  console.log("Capture recorded:", userId);
  res.send("Capture recorded");
});

app.get("/capture/latest", (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).send("userId query parameter is required");

  const userCaptures = captureEntries.filter(entry => entry.userId === userId);
  if (userCaptures.length > 0) {
    const latestCapture = userCaptures[userCaptures.length - 1];
    return res.json(latestCapture);
  }
  res.json(null);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
