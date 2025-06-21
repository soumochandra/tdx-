// index.js (Backend)
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

const User = require('./models/User');
const auth = require('./middleware/auth');

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const existing = await User.findOne({ username });
    if (existing) return res.status(400).send({ error: 'Username already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashed });
    await user.save();
    res.send({ message: 'Registered' });
  } catch (err) {
    res.status(500).send({ error: 'Registration error' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user._id }, JWT_SECRET);
      res.send({ token });
    } else {
      res.status(401).send({ error: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).send({ error: 'Login error' });
  }
});

app.get('/saved', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.send(user.savedFunds || []);
  } catch (err) {
    res.status(500).send({ error: 'Fetch saved funds failed' });
  }
});

app.post('/save', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    user.savedFunds.push(req.body.fund);
    await user.save();
    res.send({ message: 'Saved' });
  } catch (err) {
    res.status(500).send({ error: 'Save failed' });
  }
});

app.post('/remove', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    user.savedFunds = user.savedFunds.filter(f => f.id !== req.body.fund.id);
    await user.save();
    res.send({ message: 'Removed' });
  } catch (err) {
    res.status(500).send({ error: 'Remove failed' });
  }
});

app.post('/reset-password', async (req, res) => {
  const { username, newPassword } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).send({ error: 'User not found' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.send({ message: 'Password reset successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: 'Password reset error' });
  }
});

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
