require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const Queue = require('bull');

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

const requestQueue = new Queue('requestQueue');

const validateParams = (params, res) => {
  for (const param of params) {
    if (!param.value) {
      res.status(400).send(`Missing parameter: ${param.name}`);
      return false;
    }
  }
  return true;
};

const handleTrack = async (data, res) => {
  const { userId, tabVisited } = data;
  if (!validateParams([{ name: 'userId', value: userId }, { name: 'tabVisited', value: tabVisited }], res)) return;

  activeStudents[userId] = { lastActivity: Date.now(), currentTab: tabVisited };
  historyEntries.push({ userId, tabVisited, timestamp: Date.now() });

  res.send('Activity tracked');
  console.log('Activity tracked:', userId, tabVisited);
};

const handleCapture = async (data, res) => {
  const { userId, screenshot, timestamp } = data;
  if (!validateParams([{ name: 'userId', value: userId }, { name: 'screenshot', value: screenshot }, { name: 'timestamp', value: timestamp }], res)) return;

  captureEntries.push({ userId, screenshot, timestamp });
  res.send('Capture recorded');
  console.log('Capture recorded:', userId);
};

requestQueue.process(async (job, done) => {
  const { route, data, res } = job.data;

  try {
    if (route === '/track') await handleTrack(data, res);
    else if (route === '/capture') await handleCapture(data, res);

    done();
  } catch (error) {
    console.error('Error processing job:', error);
    res.status(500).send('Internal server error');
    done(error);
  }
});

app.post('/track', (req, res) => {
  requestQueue.add({ route: '/track', data: req.body, res });
});

app.post('/capture', (req, res) => {
  requestQueue.add({ route: '/capture', data: req.body, res });
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
