import express from 'express';
import fetch from 'node-fetch';
import dotenv from 'dotenv';

dotenv.config();
const router = express.Router();

router.post('/predict', async (req, res) => {
  const { question } = req.body;

  try {
    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.OPENROUTER_API_KEY}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:5173", // optional
        "X-Title": "MysticAI" // optional
      },
      body: JSON.stringify({
        model: "deepseek/deepseek-r1:free",
        messages: [{ role: "user", content: question }]
      })
    });

    const data = await response.json();
    const prediction = data.choices?.[0]?.message?.content || "No response from the oracle.";
    res.json({ prediction });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch prediction" });
  }
});

export default router;
