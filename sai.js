const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config(); // Ensure you load environment variables

const app = express();
const port = process.env.PORT || 3000;
const allowedOrigins = ['http://localhost:8081', 'https://www.sai.io', 'https://saimee.vercel.app', 'https://meetest.netlify.app'];

// Middleware
app.use(bodyParser.json());
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
}));
const saimango = process.env.MONGODB_URI;
// MongoDB connection
mongoose.connect(saimango, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected...'))
.catch(err => console.error('MongoDB connection error:', err));

// Load environment variables
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  console.error('JWT_SECRET is not defined in environment variables.');
  process.exit(1);
}

const User = require('./models/User');

// Middleware to authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401); // If no token is provided

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) return res.sendStatus(403); // If token is invalid
    req.user = user; // Attach user data to request
    next(); // Move to the next middleware or route handler
  });
}

// Get user data
app.get('/api/user', authenticateToken, async (req, res) => {
  const username = req.user.username; // Access the username from the verified token
  try {
    const user = await User.findOne({ username }, 'username email dob super_coin_bal');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error('Database query error:', err.message);
    res.status(500).json({ error: 'Database query error' });
  }
});

// Update user profile
app.put('/api/user', authenticateToken, async (req, res) => {
  const currentUsername = req.user.username; // Access the current username from the verified token
  const { newUsername, email, dob } = req.body;

  if (!newUsername) {
    return res.status(400).json({ error: 'New username is required' });
  }

  try {
    const user = await User.findOneAndUpdate(
      { username: currentUsername },
      { username: newUsername, email, dob },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    req.user.username = newUsername;
    res.json({ message: 'Profile updated successfully' });
  } catch (err) {
    console.error('Database update error:', err.message);
    res.status(500).json({ error: 'Database update error' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });
    res.status(200).json({ success: true, token });
  } catch (err) {
    console.error('Error logging in:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Signup route
app.post('/signup', async (req, res) => {
  const { username, email, password, dob } = req.body;

  if (!username || !email || !password || !dob) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword, dob });

    await user.save();
    res.status(201).json({ success: true, message: 'User registered successfully' });
  } catch (err) {
    console.error('Error registering user:', err.message);
    res.status(500).json({ success: false, message: 'Error registering user' });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
