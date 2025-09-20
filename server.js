import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

// Import your controllers
import { signup, login } from "./userController.js";
import { signupDoctor, loginDoctor } from "./doctorController.js";
import { bookConsultation, getUserConsultations } from "./consultationController.js";
import { rescheduleConsultation } from "./doctorRescheduleController.js";

// Import DB and Groq
import db from "./db.js";
import Groq from "groq-sdk";

dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// --- Setup __dirname for ES modules ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Serve static frontend files ---
app.use(express.static(path.join(__dirname, "Frontend"))); 
// Now /login.html, /dashboard.html etc. work

// --- Groq chatbot setup ---
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// ---------- USER ROUTES ----------
app.post("/user/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ success: false, message: "All fields are required" });

  try {
    await signup(name, email, password);
    res.json({ success: true, message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    if (err.code === "ER_DUP_ENTRY")
      res.status(400).json({ success: false, message: "Email already exists" });
    else res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/user/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, message: "Email and password required" });

  try {
    const user = await login(email, password);
    if (!user)
      return res.status(400).json({ success: false, message: "Invalid credentials" });
    res.json({ success: true, message: "Login successful", user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- DOCTOR ROUTES ----------
app.post("/doctor/signup", async (req, res) => {
  const { name, email, password, center, specialization } = req.body;
  if (!name || !email || !password || !center || !specialization)
    return res.status(400).json({ success: false, message: "All fields are required" });

  try {
    await signupDoctor(name, email, password, center, specialization);
    res.json({ success: true, message: "Doctor registered successfully" });
  } catch (err) {
    console.error(err);
    if (err.code === "ER_DUP_ENTRY")
      res.status(400).json({ success: false, message: "Email already exists" });
    else res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/doctor/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, message: "Email and password required" });

  try {
    const doctor = await loginDoctor(email, password);
    if (!doctor)
      return res.status(400).json({ success: false, message: "Invalid credentials" });
    res.json({ success: true, message: "Login successful", doctor });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- CONSULTATION ROUTES ----------
app.post("/consultation/book", async (req, res) => {
  const { user_id, doctor_id, date, time, reason } = req.body;
  if (!doctor_id || !date || !time || !reason)
    return res.status(400).json({ success: false, message: "All fields are required" });

  try {
    const result = await bookConsultation(user_id, doctor_id, date, time, reason);
    if (result.success)
      res.json({
        success: true,
        message: "Consultation booked successfully!",
        consultationId: result.consultationId,
      });
    else res.status(500).json({ success: false, message: "Failed to book consultation", error: result.message });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/consultation/user/:user_id", async (req, res) => {
  const { user_id } = req.params;
  try {
    const consultations = await getUserConsultations(user_id);
    res.json({ success: true, consultations });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- DOCTOR RESCHEDULE ROUTE ----------
app.put("/doctor/reschedule", async (req, res) => {
  const { consultation_id, newDate, newTime, note } = req.body;
  if (!consultation_id || !newDate || !newTime)
    return res.status(400).json({ success: false, message: "Consultation ID, new date, and new time are required." });

  try {
    const result = await rescheduleConsultation(consultation_id, newDate, newTime, note);
    if (result.success) res.json(result);
    else res.status(500).json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

// ---------- CHATBOT ROUTE ----------
app.post("/chat", async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || message.trim() === "") return res.status(400).json({ error: "No message provided" });

    const completion = await groq.chat.completions.create({
      model: "llama-3.1-8b-instant",
      messages: [
        { role: "system", content: "You are a helpful chatbot for PrakritiPath" },
        { role: "user", content: message }
      ]
    });

    const reply = completion.choices[0]?.message?.content || "Sorry, I couldn’t generate a reply.";
    res.json({ reply });
  } catch (err) {
    console.error("Chatbot error:", err);
    res.status(500).json({ error: "Server error. Please try again later." });
  }
});

// ---------- START SERVER ----------
const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0"; // listen on all network interfaces
app.listen(PORT, HOST, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});


