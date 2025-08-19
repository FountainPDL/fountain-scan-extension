// backend/routes/keywords.js
import express from "express";
import { supabase } from "../services/supabase.js";

const router = express.Router();

// Add a keyword
router.post("/", async (req, res) => {
  const { keyword, severity } = req.body;

  const { error } = await supabase.from("detection_keywords").insert([
    { keyword, severity, timestamp: new Date() }
  ]);

  if (error) return res.status(400).json({ error: error.message });
  res.json({ success: true });
});

// Get all keywords
router.get("/", async (req, res) => {
  const { data, error } = await supabase.from("detection_keywords").select("*");

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Delete a keyword
router.delete("/:id", async (req, res) => {
  const { id } = req.params;

  const { error } = await supabase
    .from("detection_keywords")
    .delete()
    .eq("id", id);

  if (error) return res.status(400).json({ error: error.message });
  res.json({ success: true });
});

export default router;
