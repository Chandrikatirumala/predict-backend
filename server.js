import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import fetch from 'node-fetch';
import nodemailer from 'nodemailer';
import User from './models/User.js';
import predictRoute from './routes/predictRoute.js';

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

// MongoDB URI
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'https://predict-frontend-xgy7-659jc0phc.vercel.app'], // both local and deployed
  credentials: true
}));
app.use(express.json());

// DB Connection
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// Auth Middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Routes
app.use('/api', predictRoute);

// Signup Route
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ message: 'User signed up successfully', token });
  } catch (err) {
    res.status(500).json({ error: 'Server error during signup' });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token, user });
  } catch (err) {
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Protected User Routes
app.get('/users', authenticate, async (req, res) => {
  const users = await User.find().select('-password');
  res.json(users);
});
app.put('/users/:id', authenticate, async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true }).select('-password');
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ message: 'User updated', user });
});
app.delete('/users/:id', authenticate, async (req, res) => {
  const user = await User.findByIdAndDelete(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ message: 'User deleted' });
});

// Contact Form Route
app.post('/api/contact', async (req, res) => {
  const { name, birthDate, email, question } = req.body;
  if (!name || !birthDate || !email || !question) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: `"MysticAI" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER,
      subject: '🔮 New Contact Form Submission',
      html: `
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Birth Date:</strong> ${birthDate}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Question:</strong> ${question}</p>
      `,
    });

    res.status(200).json({ success: true, message: 'Email sent successfully!' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send email.' });
  }
});

// Fallback Prediction API
app.post('/api/predict-fallback', async (req, res) => {
  const { question } = req.body;
  if (!question) return res.status(400).json({ error: 'Question is required' });

  try {
    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'http://localhost:5173',
        'X-Title': 'MysticAI',
      },
      body: JSON.stringify({
        model: 'deepseek/deepseek-r1:free',
        messages: [{ role: 'user', content: question }],
      }),
    });

    const data = await response.json();
    const prediction = data.choices?.[0]?.message?.content || '🔮 The spirits are silent...';
    res.json({ prediction });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get prediction from AI' });
  }
});

// Health check
app.get('/', (req, res) => {
  res.send('✅ Predict Backend is working!');
});

app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
