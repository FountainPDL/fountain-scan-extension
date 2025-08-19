// backend/server.js
import express from "express";
import cors from "cors";
import { supabase } from "./services/supabase.js"; // <- make sure supabase.js exports named { supabase }

import blacklistRoutes from "./routes/blacklist.js";
import reportRoutes from "./routes/reports.js";
import warningRoutes from "./routes/logs.js";
import keywordRoutes from "./routes/keywords.js";

const app = express();
app.use(cors());
app.use(express.json());

// Route: Add report
app.post("/report", async (req, res) => {
  const { url, reason, email } = req.body;
  const { data, error } = await supabase.from("user_reports").insert([
    { reported_url: url, report_reason: reason, user_email: email }
  ]);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ success: true, data });
});

// Route: Get blacklist
app.get("/blacklist", async (req, res) => {
  const { data, error } = await supabase.from("blacklisted_sites").select("*");
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Route: Log warning
app.post("/logs", async (req, res) => {
  const { site_url, detection_score, keywords } = req.body;
  const { error } = await supabase.from("warning_logs").insert([
    { site_url, detection_score, keywords, time_detected: new Date().toISOString() }
  ]);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// Mount routers
app.use("/blacklist", blacklistRoutes);
app.use("/reports", reportRoutes);
app.use("/warnings", warningRoutes);
app.use("/keywords", keywordRoutes);

app.get("/", (req, res) => res.send("Fountain Scan Backend Running"));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Fountain Scan backend running at http://localhost:${PORT}`)
);

export default app;
