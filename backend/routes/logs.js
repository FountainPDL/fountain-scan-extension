// backend/routes/logs.js
import express from "express";
import { supabase } from "../services/supabase.js";

const router = express.Router();

// Add a warning log
router.post("/", async (req, res) => {
  const { user_email, message, severity } = req.body;

  const { error } = await supabase.from("warning_logs").insert([
    { user_email, message, severity, timestamp: new Date() }
  ]);

  if (error) return res.status(400).json({ error: error.message });
  res.json({ success: true });
});

// Get all warning logs
router.get("/", async (req, res) => {
  const { data, error } = await supabase.from("warning_logs").select("*");

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Get warnings by user
router.get("/user/:email", async (req, res) => {
  const { email } = req.params;

  const { data, error } = await supabase
    .from("warning_logs")
    .select("*")
    .eq("user_email", email);

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

export default router;
