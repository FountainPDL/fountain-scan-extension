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

// Helper function to check if URL is already blacklisted
async function isUrlBlacklisted(url) {
  const { data, error } = await supabase
    .from("blacklisted_sites")
    .select("id")
    .eq("domain_url", url)
    .single();
  
  return !error && data;
}

// Helper function to add URL to blacklist
async function addToBlacklist(url, reason, reporterEmail) {
  try {
    const { data, error } = await supabase
      .from("blacklisted_sites")
      .insert([{
        domain_url: url,
        reason: reason,
        added_by: reporterEmail || 'auto-report-system',
        date_added: new Date().toISOString()
      }]);
    
    if (error) {
      console.error("Error adding to blacklist:", error);
      return { success: false, error };
    }
    
    console.log(`✅ Auto-blacklisted: ${url}`);
    return { success: true, data };
  } catch (err) {
    console.error("Exception adding to blacklist:", err);
    return { success: false, error: err };
  }
}

// Route: Add report (now with auto-blacklisting)
app.post("/report", async (req, res) => {
  const { url, reason, email } = req.body;
  
  try {
    // Step 1: Add the report to user_reports table
    const { data: reportData, error: reportError } = await supabase
      .from("user_reports")
      .insert([{
        reported_url: url,
        report_reason: reason,
        user_email: email
      }]);
    
    if (reportError) {
      return res.status(400).json({ error: reportError.message });
    }
    
    // Step 2: Check if URL is already blacklisted
    const alreadyBlacklisted = await isUrlBlacklisted(url);
    
    let blacklistResult = null;
    
    if (!alreadyBlacklisted) {
      // Step 3: Auto-add to blacklist if not already there
      blacklistResult = await addToBlacklist(url, reason, email);
      
      if (!blacklistResult.success) {
        console.warn(`Failed to auto-blacklist ${url}:`, blacklistResult.error);
        // Still return success for the report, even if blacklisting failed
        return res.json({
          success: true,
          data: reportData,
          blacklisted: false,
          blacklist_error: blacklistResult.error?.message || "Unknown error"
        });
      }
    }
    
    // Step 4: Return success response
    res.json({
      success: true,
      data: reportData,
      blacklisted: !alreadyBlacklisted,
      already_blacklisted: !!alreadyBlacklisted,
      message: alreadyBlacklisted 
        ? "Report submitted. URL was already blacklisted." 
        : "Report submitted and URL automatically added to blacklist."
    });
    
  } catch (error) {
    console.error("Error processing report:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Route: Get blacklist
app.get("/blacklist", async (req, res) => {
  const { data, error } = await supabase.from("blacklisted_sites").select("*");
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Route: Log warning
app.post("/logs", async (req, res) => {
  const { domain_url, detection_score, keywords } = req.body;
  const { error } = await supabase.from("warning_logs").insert([
    { domain_url, detection_score, keywords, time_detected: new Date().toISOString() }
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