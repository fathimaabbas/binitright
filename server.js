/************************************
 * LOAD ENVIRONMENT VARIABLES
 ************************************/
require('dotenv').config();

/************************************
 * IMPORT REQUIRED MODULES
 ************************************/
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const path = require('path');

/************************************
 * INITIALIZE EXPRESS APP
 ************************************/
const app = express();

/************************************
 * MIDDLEWARE CONFIGURATION
 ************************************/
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('view'));

/************************************
 * DATABASE CONNECTION
 ************************************/
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT
});

/************************************
 * JWT CONFIG
 ************************************/
const JWT_SECRET = process.env.JWT_SECRET;

/************************************
 * JWT AUTH MIDDLEWARE
 ************************************/
function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(403).json({ message: 'Token required' });

    const token = authHeader.split(' ')[1];

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: 'Invalid token' });
        req.user = decoded;
        next();
    });
}

/************************************
 * REGISTER API
 ************************************/
app.post('/register', async (req, res) => {
    const { email, password, confirm_password, role } = req.body;

    if (!email || !password || !confirm_password || !role)
        return res.status(400).send('All fields required');

    if (password !== confirm_password)
        return res.status(400).send('Passwords do not match');

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.query(
            'INSERT INTO users (email, password, role) VALUES ($1, $2, $3)',
            [email, hashedPassword, role]
        );

        res.redirect('/login');
    } catch (err) {
        if (err.code === '23505')
            res.status(400).send('Email already exists');
        else
            res.status(500).send('Server error');
    }
});

/************************************
 * LOGIN API
 ************************************/
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).send('All fields required');

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0)
            return res.status(401).send('Invalid email or password');

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch)
            return res.status(401).send('Invalid email or password');

        const token = jwt.sign(
            { id: user.id, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ message: 'Login successful', token });

    } catch {
        res.status(500).send('Server error');
    }
});

/************************************
 * 🔐 PROFILE API (NEW)
 ************************************/
app.get('/profile', verifyToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT email, role FROM users WHERE id = $1',
            [req.user.id]
        );

        res.json(result.rows[0]);
    } catch {
        res.status(500).json({ message: 'Error fetching profile' });
    }
});

/************************************
 * PAGE ROUTES
 ************************************/
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'view', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'view', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'view', 'register.html'));
});

/************************************
 * START SERVER
 ************************************/
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
