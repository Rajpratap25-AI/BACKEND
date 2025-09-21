import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import jwt from "jsonwebtoken";
import mysql from "mysql2/promise";

// Import controllers (make sure ye files exist aur functions export ho rahe ho)
import { signup, login } from "./userController.js";
import { signupDoctor, loginDoctor } from "./doctorController.js";
import { bookConsultation, getUserConsultations } from "./consultationController.js";
import { rescheduleConsultation } from "./doctorRescheduleController.js";

// Load environment variables
dotenv.config();

// Create Express app
const app = express();

// Enable CORS for frontend URL
app.use(cors({
    origin: ["https://prakritipath.onrender.com", "http://localhost:5500"], // frontend URLs
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
}));

app.use(bodyParser.json());

// Setup __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve static frontend files (optional, if needed)
app.use(express.static(path.join(__dirname, "Frontend")));

// ------------------ Database Connection ------------------
const db = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

console.log("✅ Database connected successfully!");

// ------------------ JWT Security ------------------
const tokenBlacklist = new Set();

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ success: false, message: "Unauthorized" });

    if (tokenBlacklist.has(token)) return res.status(403).json({ success: false, message: "Token invalidated" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: "Invalid token" });
        req.user = user;
        next();
    });
};

// ------------------ USER ROUTES ------------------
app.post("/user/signup", async (req, res) => {
    const { name, email, password, age, contact, gender } = req.body;

    if (!name || !email || !password || !age || !contact || !gender) 
        return res.status(400).json({ success: false, message: "All fields are required" });

    try {
        await signup(name, email, password, age, contact, gender);
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
    if (!email || !password) return res.status(400).json({ success: false, message: "Email and password required" });

    try {
        const result = await login(email, password); // { user, token }
        if (!result) return res.status(400).json({ success: false, message: "Invalid credentials" });

        res.json({ success: true, message: "Login successful", user: result.user, token: result.token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// ------------------ DOCTOR ROUTES ------------------
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
    if (!email || !password) return res.status(400).json({ success: false, message: "Email and password required" });

    try {
        const result = await loginDoctor(email, password); // { doctor, token }
        if (!result) return res.status(400).json({ success: false, message: "Invalid credentials" });

        res.json({ success: true, message: "Login successful", doctor: result.doctor, token: result.token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// ------------------ CONSULTATION ROUTES ------------------
app.post("/consultation/book", authenticateToken, async (req, res) => {
    const { user_id, doctor_id, date, time, reason } = req.body;
    if (!doctor_id || !date || !time || !reason)
        return res.status(400).json({ success: false, message: "All fields are required" });

    try {
        const result = await bookConsultation(user_id, doctor_id, date, time, reason);
        if (result.success) res.json({ success: true, message: "Consultation booked", consultationId: result.consultationId });
        else res.status(500).json({ success: false, message: result.message });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.get("/user/:userId/history", authenticateToken, async (req, res) => {
    const { userId } = req.params;
    if (req.user.id !== parseInt(userId)) return res.status(403).json({ success: false, message: "Forbidden" });

    try {
        const consultations = await getUserConsultations(userId);
        res.json({ success: true, consultations });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// ------------------ LOGOUT ------------------
app.post("/logout", authenticateToken, (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token) tokenBlacklist.add(token);
    res.json({ success: true, message: "Logged out successfully" });
});

// ------------------ START SERVER ------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
