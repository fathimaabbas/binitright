/************************************
 * LOAD ENV VARIABLES
 ************************************/
require('dotenv').config();

/************************************
 * IMPORT MODULES
 ************************************/
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const multer = require('multer');

/************************************
 * INIT APP
 ************************************/
const app = express();

/************************************
 * MIDDLEWARE
 ************************************/
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'view')));

/************************************
 * MULTER CONFIG
 ************************************/
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'view/uploads'));
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

/************************************
 * DATABASE CONFIG
 ************************************/
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT
});

/************************************
 * INIT DATABASE
 ************************************/
async function initDb() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS recycling_requests (
            id SERIAL PRIMARY KEY,
            customer_name VARCHAR(255),
            contact_number VARCHAR(20),
            location TEXT,
            waste_type VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            expected_price NUMERIC(10,2) NOT NULL,
            image_url TEXT NOT NULL,
            status VARCHAR(50) DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);

    console.log("Database initialized");
}
initDb();

/************************************
 * AUTH APIs
 ************************************/
app.post('/register', async (req, res) => {
    const { email, password, confirm_password, role } = req.body;
    if (password !== confirm_password) return res.send("Passwords mismatch");

    const hash = await bcrypt.hash(password, 10);
    await pool.query(
        "INSERT INTO users (email, password, role) VALUES ($1,$2,$3)",
        [email, hash, role]
    );
    res.redirect('/login.html');
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (result.rows.length === 0) return res.send("Invalid login");

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.send("Invalid login");

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
    res.json({ token, role: user.role });
});

/************************************
 * SUBMIT RECYCLING LISTING
 ************************************/
app.post('/submit-listing', upload.single('image'), async (req, res) => {
    const {
        customerName,
        contactNumber,
        location,
        wasteType,
        description,
        expectedPrice
    } = req.body;

    const imagePath = `/uploads/${req.file.filename}`;

    await pool.query(
        `INSERT INTO recycling_requests
        (customer_name, contact_number, location, waste_type, description, expected_price, image_url)
        VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [
            customerName || "Anonymous",
            contactNumber,
            location,
            wasteType,
            description,
            expectedPrice,
            imagePath
        ]
    );

    res.redirect('/recycling.html?success=true');
});

/************************************
 * GET ALL RECYCLING REQUESTS
 ************************************/
app.get('/api/recycling', async (req, res) => {
    const result = await pool.query(
        "SELECT * FROM recycling_requests ORDER BY created_at DESC"
    );
    res.json(result.rows);
});

/************************************
 * ACCEPT REQUEST
 ************************************/
app.post('/api/recycling/:id/accept', async (req, res) => {
    await pool.query(
        "UPDATE recycling_requests SET status='Accepted' WHERE id=$1",
        [req.params.id]
    );
    res.json({ message: "Request accepted" });
});

/************************************
 * MARK COLLECTED
 ************************************/
app.post('/api/recycling/:id/collect', async (req, res) => {
    await pool.query(
        "UPDATE recycling_requests SET status='Collected' WHERE id=$1",
        [req.params.id]
    );
    res.json({ message: "Collected" });
});
/************************************
 * DELETE COLLECTED REQUEST
 ************************************/
app.delete('/api/recycling/:id', async (req, res) => {
    try {
        // Only delete if already collected
        const result = await pool.query(
            "DELETE FROM recycling_requests WHERE id = $1 AND status = 'Collected' RETURNING *",
            [req.params.id]
        );

        if (result.rowCount === 0) {
            return res.status(400).json({ message: "Only collected items can be deleted" });
        }

        res.json({ message: "Collected request deleted" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error while deleting" });
    }
});

/************************************
 * PAGE ROUTES
 ************************************/
app.get('/', (req, res) =>
    res.sendFile(path.join(__dirname, 'view/index.html'))
);

app.get('/recycling', (req, res) =>
    res.sendFile(path.join(__dirname, 'view/recycling.html'))
);

app.get('/official-dashboard', (req, res) =>
    res.sendFile(path.join(__dirname, 'view/official-dashboard.html'))
);

/************************************
 * START SERVER
 ************************************/
app.listen(3000, () =>
    console.log("Server running on http://localhost:3000")
);
