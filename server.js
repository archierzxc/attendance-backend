const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const SECRET = 'attendance_secret_key_change_in_production';

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'navales123',         // change to your MySQL password
    database: 'attendance_db'
});

db.connect(err => {
    if (err) { console.error('DB connection failed:', err); process.exit(1); }
    console.log('Connected to MySQL');
    initDB();
});

function initDB() {
    db.query(`CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    db.query(`CREATE TABLE IF NOT EXISTS subjects (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(100) NOT NULL,
        code VARCHAR(50) NOT NULL,
        schedule VARCHAR(100),
        total_classes INT DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    db.query(`CREATE TABLE IF NOT EXISTS attendance (
        id INT AUTO_INCREMENT PRIMARY KEY,
        subject_id INT NOT NULL,
        user_id INT NOT NULL,
        status ENUM('Present','Absent','Leave') NOT NULL,
        date DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    console.log('Database tables ready');
}

// Middleware: verify JWT
function auth(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    try {
        req.user = jwt.verify(token, SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// ── AUTH ──────────────────────────────────────────

// POST /api/register
app.post('/api/register', (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
        return res.status(400).json({ error: 'All fields required' });

    const hashed = bcrypt.hashSync(password, 10);
    db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
        [name, email, hashed], (err, result) => {
            if (err) return res.status(400).json({ error: 'Email already exists' });
            const token = jwt.sign({ id: result.insertId, name, email }, SECRET, { expiresIn: '7d' });
            res.json({ token, user: { id: result.insertId, name, email } });
        });
});

// POST /api/login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: 'All fields required' });

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, rows) => {
        if (err || rows.length === 0)
            return res.status(401).json({ error: 'Invalid credentials' });

        const user = rows[0];
        if (!bcrypt.compareSync(password, user.password))
            return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
    });
});

// ── SUBJECTS ──────────────────────────────────────

// GET /api/subjects
app.get('/api/subjects', auth, (req, res) => {
    const sql = `
        SELECT s.*,
            COUNT(CASE WHEN a.status='Present' THEN 1 END) AS present_count,
            COUNT(CASE WHEN a.status='Absent'  THEN 1 END) AS absent_count,
            COUNT(CASE WHEN a.status='Leave'   THEN 1 END) AS leave_count
        FROM subjects s
        LEFT JOIN attendance a ON a.subject_id = s.id
        WHERE s.user_id = ?
        GROUP BY s.id
        ORDER BY s.id ASC`;
    db.query(sql, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// POST /api/subjects
app.post('/api/subjects', auth, (req, res) => {
    const { name, code, schedule, total_classes } = req.body;
    if (!name || !code)
        return res.status(400).json({ error: 'Name and code required' });

    db.query('INSERT INTO subjects (user_id, name, code, schedule, total_classes) VALUES (?,?,?,?,?)',
        [req.user.id, name, code, schedule || '', total_classes || 0], (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: result.insertId, name, code, schedule, total_classes, present_count: 0, absent_count: 0, leave_count: 0 });
        });
});

// PUT /api/subjects/:id
app.put('/api/subjects/:id', auth, (req, res) => {
    const { name, code, schedule, total_classes } = req.body;
    db.query('UPDATE subjects SET name=?, code=?, schedule=?, total_classes=? WHERE id=? AND user_id=?',
        [name, code, schedule, total_classes, req.params.id, req.user.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Updated' });
        });
});

// DELETE /api/subjects/:id
app.delete('/api/subjects/:id', auth, (req, res) => {
    db.query('DELETE FROM subjects WHERE id=? AND user_id=?',
        [req.params.id, req.user.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Deleted' });
        });
});

// ── ATTENDANCE ────────────────────────────────────

// POST /api/attendance  (mark single record)
app.post('/api/attendance', auth, (req, res) => {
    const { subject_id, status, date } = req.body;
    if (!subject_id || !status || !date)
        return res.status(400).json({ error: 'subject_id, status, date required' });

    // Upsert: update if same subject+user+date exists
    db.query(`INSERT INTO attendance (subject_id, user_id, status, date)
              VALUES (?,?,?,?)
              ON DUPLICATE KEY UPDATE status=VALUES(status)`,
        [subject_id, req.user.id, status, date], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Attendance saved' });
        });
});

// GET /api/attendance/:subject_id  (history for one subject)
app.get('/api/attendance/:subject_id', auth, (req, res) => {
    db.query('SELECT * FROM attendance WHERE subject_id=? AND user_id=? ORDER BY date DESC',
        [req.params.subject_id, req.user.id], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
});

// GET /api/stats  (overall stats)
app.get('/api/stats', auth, (req, res) => {
    const sql = `
        SELECT
            COUNT(CASE WHEN status='Present' THEN 1 END) AS total_present,
            COUNT(CASE WHEN status='Absent'  THEN 1 END) AS total_absent,
            COUNT(CASE WHEN status='Leave'   THEN 1 END) AS total_leave,
            COUNT(*) AS total_records
        FROM attendance WHERE user_id=?`;
    db.query(sql, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows[0]);
    });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
