import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import jwt from 'jsonwebtoken'; // For security

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

// --- 🔐 START: SECURITY IMPLEMENTATION ---

// This will store invalidated tokens. In a production app, use a database like Redis.
const tokenBlacklist = new Set();

// Middleware to protect routes by verifying a token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"

    if (token == null) {
        return res.sendStatus(401); // Unauthorized if no token
    }

    // Check if the token has been logged out (is in the blacklist)
    if (tokenBlacklist.has(token)) {
        return res.sendStatus(403); // Forbidden if token is blacklisted
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Forbidden if token is invalid
        }
        req.user = user; // Add the decoded user payload (e.g., { id, role }) to the request
        next(); // Proceed to the next function/route handler
    });
};

// --- END: SECURITY IMPLEMENTATION ---

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
        const result = await login(email, password); // Your controller must return { user, token }
        if (!result)
            return res.status(400).json({ success: false, message: "Invalid credentials" });
        
        // Send the token back to the frontend
        res.json({ success: true, message: "Login successful", user: result.user, token: result.token }); 
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
        const result = await loginDoctor(email, password); // Your controller must return { doctor, token }
        if (!result)
            return res.status(400).json({ success: false, message: "Invalid credentials" });

        // Send the token back to the frontend
        res.json({ success: true, message: "Login successful", doctor: result.doctor, token: result.token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// --- FETCH ALL APPOINTMENTS FOR A DOCTOR ---
app.get("/doctor/appointments/:doctorId", authenticateToken, async (req, res) => {
    try {
        const { doctorId } = req.params;

        // Ensure the logged-in user is a doctor and matches the requested doctorId
        if (req.user.role !== 'doctor' || req.user.id !== parseInt(doctorId)) {
            return res.status(403).json({ success: false, message: "Forbidden: You can only view your own appointments." });
        }

        const query = `
            SELECT 
                c.id, c.date, c.time, c.reason,
                u.name AS patient_name,
                u.contact AS patient_contact,
                u.gender AS patient_gender
            FROM consultations c
            JOIN users u ON c.user_id = u.id
            WHERE c.doctor_id = ?
            ORDER BY c.date, c.time;
        `;

        const [appointments] = await db.query(query, [doctorId]);

        res.status(200).json(appointments);

    } catch (error) {
        console.error("Error fetching appointments:", error);
        res.status(500).json({ success: false, message: "Server error while fetching appointments." });
    }
});


// ---------- ADMIN/SECURE LOGOUT ROUTE ----------
app.post('/admin/logout', authenticateToken, (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        tokenBlacklist.add(token);
    }
    
    console.log('Token blacklisted. User logged out.');
    res.status(200).json({ success: true, message: 'Logged out successfully' });
});


// ---------- PROTECTED CONSULTATION AND HISTORY ROUTES ----------
app.post("/consultation/book", authenticateToken, async (req, res) => {
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

app.get("/user/:userId/history", authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;

        if (req.user.id !== parseInt(userId)) {
            return res.status(403).json({ success: false, message: "Forbidden" });
        }

        const consultations = await getUserConsultations(userId);
        const prescriptions = ["Medication A - 2 times a day", "Medication B - 1 time a day"];
        
        res.status(200).json({
            success: true,
            consultations: consultations,
            prescriptions: prescriptions
        });

    } catch (error) {
        console.error("Error fetching user history:", error);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// --- FETCH ALL LAB REPORTS FOR A USER ---
app.get("/user/:userId/reports", authenticateToken, (req, res) => {
    const { userId } = req.params;

    if (req.user.id !== parseInt(userId)) {
        return res.status(403).json({ success: false, message: "Forbidden" });
    }

    const mockReports = [
        { title: "Blood Test Report", date: "2025-09-12", doctor: "Dr. Mehta", summary: "Hemoglobin and RBC count normal. Vitamin D slightly low.", pdfUrl: "#" },
        { title: "X-Ray Report", date: "2025-09-08", doctor: "Dr. Sharma", summary: "Chest X-Ray normal. No major abnormalities detected.", pdfUrl: "#" },
        { title: "Ayurvedic Diagnosis Report", date: "2025-09-05", doctor: "Dr. Raghavan", summary: "Patient shows mild Vata imbalance. Recommended Panchakarma therapy.", pdfUrl: "#" }
    ];
    res.status(200).json(mockReports);
});


// ---------- DOCTOR RESCHEDULE ROUTE ----------
app.put("/doctor/reschedule", authenticateToken, async (req, res) => {
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

// ---------- BOOK THERAPY ROUTE ----------
app.post("/book-therapy", authenticateToken, async (req, res) => {
    try {
        const { therapy, userId } = req.body;

        if (req.user.id !== userId) {
            return res.status(403).json({ success: false, message: "Forbidden: You can only book therapy for yourself." });
        }
        if (!therapy) {
            return res.status(400).json({ success: false, message: "Therapy selection is required." });
        }

        console.log(`--- New Therapy Selection ---`);
        console.log(`User ID ${userId} selected therapy: ${therapy}`);
        console.log("----------------------------");
        
        res.status(200).json({ success: true, message: "Therapy selected successfully!" });

    } catch (error) {
        console.error("Error booking therapy:", error);
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

// ---------- CONTACT FORM ROUTE ----------
app.post("/contact", (req, res) => {
    const { name, email, message } = req.body;
    if (!name || !email || !message) {
        return res.status(400).json({ success: false, message: "All fields are required." });
    }
    console.log("--- New Contact Form Submission ---");
    console.log(`Name: ${name}`);
    console.log(`Email: ${email}`);
    console.log(`Message: ${message}`);
    console.log("---------------------------------");
    res.status(200).json({ success: true, message: "Message received successfully!" });
});


// ---------- START SERVER ----------
const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0"; // Listen on all network interfaces
app.listen(PORT, HOST, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});