// backend/routes/blacklist.js
import express from "express";
import { supabase } from "../services/supabase.js";

const router = express.Router();

// Add domain to blacklist
router.post("/", async (req, res) => {
  const { domain, reason } = req.body;

  const { error } = await supabase.from("blacklisted_sites").insert([
    { domain, reason, timestamp: new Date() }
  ]);

  if (error) return res.status(400).json({ error: error.message });
  res.json({ success: true });
});

// Get all blacklisted domains
router.get("/", async (req, res) => {
  const { data, error } = await supabase.from("blacklisted_sites").select("*");

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Check if a specific domain is blacklisted
router.get("/:domain", async (req, res) => {
  const domain = req.params.domain;

  const { data, error } = await supabase
    .from("blacklisted_sites")
    .select("*")
    .eq("domain", domain);

  if (error) return res.status(400).json({ error: error.message });
  res.json({ blacklisted: data.length > 0, details: data });
});

export default router;
