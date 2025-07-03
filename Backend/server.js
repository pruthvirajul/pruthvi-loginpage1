const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const multer = require('multer');
const cors = require('cors');

const app = express();
const port = 4149;

// Middleware
app.use(express.json());
app.use(cors());

// PostgreSQL connection
const pool = new Pool({
    user: 'postgres',
    host: 'postgres',
    database: 'login',
    password: 'admin321',
    port: 5432,
});

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Initialize database (create users table if it doesn't exist)
const initDatabase = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(30) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                profile_picture TEXT
            )
        `);
        console.log('Users table created or already exists');
    } catch (error) {
        console.error('Error creating users table:', error.message);
        process.exit(1); // Exit if table creation fails
    }
};

// Call initDatabase when the server starts
initDatabase().then(() => {
    // Start the server only after the database is initialized
    app.listen(port, () => {
        console.log(`Server running on http://13.48.136.225:${port}`);
    });
});

// Helper function to validate email
const validateEmail = (email) => {
    const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return re.test(email);
};

// Signup endpoint
app.post('/api/signup', upload.single('profilePicture'), async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const profilePicture = req.file ? req.file.buffer.toString('base64') : null;

        // Validate inputs
        if (!name || !email || !password || !profilePicture) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email address' });
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        // Check if name or email already exists
        const nameCheck = await pool.query('SELECT * FROM users WHERE name = $1', [name]);
        if (nameCheck.rows.length > 0) {
            return res.status(400).json({ error: 'Username already registered' });
        }

        const emailCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (emailCheck.rows.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into database
        await pool.query(
            'INSERT INTO users (name, email, password, profile_picture) VALUES ($1, $2, $3, $4)',
            [name, email, hashedPassword, profilePicture]
        );

        res.status(201).json({ message: 'Sign Up successful' });
    } catch (error) {
        console.error('Signup error:', error.message);
        res.status(500).json({ error: 'Server error', details: error.message });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password, remember } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Find user
        const result = await pool.query('SELECT * FROM users WHERE name = $1', [username]);
        const user = result.rows[0];

        if (!user) {
            return res.status(400).json({ error: 'Username not found' });
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Incorrect password' });
        }

        res.status(200).json({ message: 'Login successful', username });
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({ error: 'Server error', details: error.message });
    }
});

// Forgot password endpoint
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email, newPassword, confirmPassword } = req.body;

        if (!email || !newPassword || !confirmPassword) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email address' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }

        // Check if email exists
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Email not registered' });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password
        await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);

        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('Forgot password error:', error.message);
        res.status(500).json({ error: 'Server error', details: error.message });
    }
});