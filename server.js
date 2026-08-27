const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

// Security Middleware
app.use(helmet());

// Rate Limiting - Fixed version
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    skip: (req) => req.ip === '::1' || req.ip === '127.0.0.1',
    trustProxy: true
});
app.use('/api', limiter);

// CORS Configuration
app.use(cors({
    origin: [
        'http://localhost:3000',
        'http://localhost:5173',
        'https://mxrollover.onrender.com',
        'https://mxrollover-backend-pd7s.onrender.com'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// ============================================
// DATABASE CONNECTION
// ============================================
const pool = mysql.createPool(process.env.DB_URI);

// Test database connection
pool.getConnection()
    .then(() => console.log('✅ MySQL database connected successfully'))
    .catch(err => console.error('❌ Database connection failed:', err.message));

// ============================================
// JWT HELPER FUNCTIONS
// ============================================
const generateToken = (userId, username) => {
    return jwt.sign(
        { userId, username },
        process.env.JWT_SECRET || 'default-secret-change-this',
        { expiresIn: '7d' }
    );
};

const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-change-this');
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }
};

// ============================================
// AUTHENTICATION ROUTES
// ============================================

// REGISTER
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required.' });
        }

        if (username.length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters.' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters.' });
        }

        const [existing] = await pool.query(
            'SELECT id FROM users WHERE username = ?',
            [username]
        );

        if (existing.length > 0) {
            return res.status(400).json({ error: 'Username already taken.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await pool.query(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword]
        );

        const token = generateToken(result.insertId, username);

        res.status(201).json({
            message: 'User registered successfully!',
            token,
            username,
            userId: result.insertId
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            error: 'Registration failed. Please try again.'
        });
    }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required.' });
        }

        const [users] = await pool.query(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        const token = generateToken(user.id, user.username);

        res.json({
            message: 'Login successful!',
            token,
            username: user.username,
            userId: user.id
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            error: 'Login failed. Please try again.'
        });
    }
});

// GET ALL ROLLOVER RUNS
app.get('/api/rollovers', verifyToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        const [runs] = await pool.query(
            'SELECT * FROM rollovers WHERE user_id = ? ORDER BY created_at DESC',
            [userId]
        );

        for (let run of runs) {
            const [steps] = await pool.query(
                'SELECT * FROM bet_steps WHERE rollover_id = ? ORDER BY day_number ASC',
                [run.id]
            );
            run.steps = steps;
        }

        res.json(runs);

    } catch (error) {
        console.error('Error fetching rollovers:', error);
        res.status(500).json({ error: 'Failed to fetch rollover data.' });
    }
});

// CREATE ROLLOVER RUN
app.post('/api/rollovers', verifyToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { title, target_goal, initial_stake, base_odds } = req.body;

        if (!title || !initial_stake) {
            return res.status(400).json({ error: 'Title and initial stake are required.' });
        }

        const connection = await pool.getConnection();
        await connection.beginTransaction();

        try {
            const [result] = await connection.query(
                `INSERT INTO rollovers 
                (user_id, title, target_goal, initial_stake, base_odds, current_stake, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    userId, 
                    title, 
                    target_goal || '1M Goal', 
                    initial_stake, 
                    base_odds || 1.00,
                    initial_stake,
                    'active'
                ]
            );

            const runId = result.insertId;
            let currentStake = parseFloat(initial_stake);

            for (let day = 1; day <= 10; day++) {
                const odds = 1.20 + (day * 0.05);
                const winAmount = currentStake * odds;
                
                await connection.query(
                    `INSERT INTO bet_steps 
                    (rollover_id, day_number, stake, odds, win_amount, status) 
                    VALUES (?, ?, ?, ?, ?, ?)`,
                    [
                        runId,
                        day,
                        Math.round(currentStake),
                        parseFloat(odds.toFixed(2)),
                        Math.round(winAmount),
                        'pending'
                    ]
                );

                currentStake = winAmount;
            }

            await connection.commit();
            res.status(201).json({ message: 'Rollover run created successfully!', runId });

        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }

    } catch (error) {
        console.error('Error creating rollover:', error);
        res.status(500).json({ error: 'Failed to create rollover run.' });
    }
});

// UPDATE BET STATUS
app.put('/api/bets/:id', verifyToken, async (req, res) => {
    try {
        const betId = req.params.id;
        const { status } = req.body;
        const userId = req.user.userId;

        const [check] = await pool.query(
            `SELECT s.*, r.user_id 
            FROM bet_steps s
            JOIN rollovers r ON s.rollover_id = r.id
            WHERE s.id = ? AND r.user_id = ?`,
            [betId, userId]
        );

        if (check.length === 0) {
            return res.status(404).json({ error: 'Bet not found.' });
        }

        await pool.query(
            'UPDATE bet_steps SET status = ? WHERE id = ?',
            [status, betId]
        );

        if (status === 'loss') {
            await pool.query(
                'UPDATE rollovers SET status = ? WHERE id = ?',
                ['finished', check[0].rollover_id]
            );
        }

        res.json({ message: 'Bet status updated successfully!' });

    } catch (error) {
        console.error('Error updating bet:', error);
        res.status(500).json({ error: 'Failed to update bet status.' });
    }
});

// HEALTH CHECK
app.get('/api/health', async (req, res) => {
    try {
        const [result] = await pool.query('SELECT 1 as connected, NOW() as time');
        res.json({
            status: 'OK',
            database: 'Connected',
            timestamp: result[0].time,
            uptime: process.uptime()
        });
    } catch (error) {
        res.status(500).json({
            status: 'ERROR',
            database: 'Disconnected',
            error: error.message
        });
    }
});

// TEST ROUTE
app.get('/api/test', async (req, res) => {
    res.json({
        message: 'MxRollover API is running!',
        endpoints: [
            'POST /api/auth/register',
            'POST /api/auth/login',
            'GET /api/rollovers',
            'POST /api/rollovers',
            'PUT /api/bets/:id',
            'GET /api/health',
            'GET /api/test'
        ]
    });
});

// ERROR HANDLING
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error.' });
});

// START SERVER
app.listen(PORT, () => {
    console.log(`🚀 MxRollover Backend running on port ${PORT}`);
    console.log(`📊 Database: Connected to Aiven MySQL`);
    console.log(`🔒 JWT: ${process.env.JWT_SECRET ? 'Configured' : '⚠️ Using default secret'}`);
});