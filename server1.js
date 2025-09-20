// server.js
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Replace with your Gemini API key
const GEMINI_API_KEY = "AIzaSyCSI6vweUBnIzfAbcvHd_QYv4skjCjl3Es";

app.post('/api/chat', async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ success: false, message: "Message required" });

  try {
    const response = await fetch('https://generative.googleapis.com/v1beta2/models/text-bison-001:generate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GEMINI_API_KEY}`,
      },
      body: JSON.stringify({
        prompt: message,
        temperature: 0.7,
        maxOutputTokens: 200,
      }),
    });

    const data = await response.json();
    const aiReply = data?.candidates?.[0]?.content || "🤖 Sorry, I couldn't generate a response.";

    res.json({ success: true, reply: aiReply });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, reply: "Server error while fetching AI response." });
  }
});

const PORT = 5000;
app.listen(PORT, () => console.log(`✅ Chatbot backend running at http://localhost:${PORT}`));
