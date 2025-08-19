// backend/routes/reports.js
import express from "express";
import { supabase } from "../services/supabase.js";

const router = express.Router();

// Add new report
router.post("/", async (req, res) => {
  const { user_email, reported_url, report_reason } = req.body;

  const { error } = await supabase.from("user_reports").insert([
    {
      user_email,
      reported_url,
      report_reason,
      timestamp: new Date()
    }
  ]);

  if (error) return res.status(400).json({ error: error.message });
  res.json({ success: true });
});

// Get all reports
router.get("/", async (req, res) => {
  const { data, error } = await supabase.from("user_reports").select("*");

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

export default router;
