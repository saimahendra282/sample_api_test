const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise'); // Use promise-based mysql2
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000; // Use environment port or default to 3000
const allowedOrigins = ['http://localhost:8081', 'https://www.sai.io', 'https://saimee.vercel.app','https://meetest.netlify.app'];

// Middleware
app.use(bodyParser.json());
app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
}));

app.use(express.json());

// MySQL connection pool for better connection management in serverless environments
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10, // Adjust based on your needs
  queueLimit: 0
});

// Route to create the users table if it doesn't exist
app.get('/create-table', async (req, res) => {
  try {
    const sql = `
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        dob DATE NOT NULL,
        super_coin_bal INT DEFAULT 99
      )
    `;
    const [result] = await pool.query(sql);
    res.send('Users table created...');
  } catch (err) {
    console.error('Error creating table:', err.message);
    res.status(500).send('Error creating table.');
  }
});

// Middleware to authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401); // If no token is provided

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // If token is invalid
    req.user = user; // Attach user data to request
    next(); // Move to the next middleware or route handler
  });
}

// Get user data
app.get('/api/user', authenticateToken, async (req, res) => {
  const username = req.user.username; // Access the username from the verified token
  try {
    const [results] = await pool.query('SELECT username, email, dob, super_coin_bal FROM users WHERE username = ?', [username]);
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(results[0]);
  } catch (err) {
    console.error('Database query error:', err.message);
    res.status(500).json({ error: 'Database query error' });
  }
});

// Update user profile
app.put('/api/user', authenticateToken, async (req, res) => {
  const currentUsername = req.user.username; // Access the current username from the verified token
  const { newUsername, email, dob } = req.body;

  // Validate new username
  if (!newUsername) {
    return res.status(400).json({ error: 'New username is required' });
  }

  try {
    const [result] = await pool.query(
      'UPDATE users SET username = ?, email = ?, dob = ? WHERE username = ?',
      [newUsername, email, dob, currentUsername]
    );

    // Update the username in the token if needed
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
    return res.status(400).json({ success: false, message: 'Username and password are required' });
  }

  try {
    const [results] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (results.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    // Issue a JWT token
    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ success: true, token });
  } catch (err) {
    console.error('Database error:', err.message);
    res.status(500).json({ success: false, message: 'Internal server error' });
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
    const sql = 'INSERT INTO users (username, email, password, dob) VALUES (?, ?, ?, ?)';
    const values = [username, email, hashedPassword, dob];

    await pool.query(sql, values);
    res.status(201).json({ success: true, message: 'User registered successfully' });
  } catch (err) {
    console.error('Error registering user:', err.message);
    res.status(500).json({ success: false, message: 'Error registering user' });
  }
});

// Start the server (not used in serverless environments, but necessary for local testing)
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
