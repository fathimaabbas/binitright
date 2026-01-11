const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const path = require('path');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('view'));

const pool = new Pool({
    user: env.db_user,
    host: env.db_host,
    database: env.db_database,
    password: db_pass,
    port: env.db_port
});

/* REGISTER */
app.post('/register', async (req, res) => {
    const { email, password, confirm_password, role } = req.body;

    if (!email || !password || !confirm_password || !role) {
        return res.status(400).send('All fields are required');
    }

    if (password !== confirm_password) {
        return res.status(400).send('Passwords do not match');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.query(
            'INSERT INTO users(email, password, role) VALUES($1, $2, $3)',
            [email, hashedPassword, role]
        );

        res.redirect('/login');

    } catch (err) {
        console.error(err);
        if (err.code === '23505') {
            res.status(400).send('Email already exists');
        } else {
            res.status(500).send('Server error');
        }
    }
});


/* LOGIN PAGE */
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'view', 'login.html'));
});

/* REGISTER PAGE */
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'view', 'register.html'));
});

/* HOME PAGE */
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'view', 'index.html'));
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
