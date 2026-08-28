const express = require('express');
const cors = require('cors');
require('dotenv').config();
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================
// CORS - allowlist (add any production origins here)
// ============================================
const allowedOrigins = [
  'http://localhost:3000',
  'https://mxrollover.onrender.com',
  'https://mxrollover-backend-jpyd.onrender.com', // add your Render URL(s)
  'https://moonlightz255.github.io',
  'https://moonlightz255.github.io/mx'
];

app.use(cors({
  origin: (origin, callback) => {
    // allow requests with no origin (e.g. mobile apps, curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    }
    return callback(new Error('CORS policy: origin not allowed: ' + origin));
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ensure OPTIONS preflight returns quickly
app.options('*', cors());

app.use(express.json({ limit: '50mb' })); // Allow large base64 images

// ============================================
// ROOT
// ============================================
app.get('/', (req, res) => {
  res.send('MxRollover Backend is running!');
});

// ============================================
// DATABASE CONNECTION (Aiven-friendly)
// ============================================
console.log('🔍 Connecting to database...');

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: parseInt(process.env.DB_PORT || '11292', 10),
    // Aiven requires TLS; if you mount CA, provide it via DB_CA_PATH env
    ssl: (() => {
      try {
        if (process.env.DB_CA_PATH) {
          return { ca: fs.readFileSync(process.env.DB_CA_PATH, 'utf8'), rejectUnauthorized: true };
        } else {
          // If you don't provide CA, allow TLS but don't reject - safer for quick testing.
          return { rejectUnauthorized: false };
        }
      } catch (e) {
        console.warn('Could not load DB CA file:', e.message);
        return { rejectUnauthorized: false };
      }
    })(),
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 60000
});

const promisePool = pool.promise();

// ============================================
// DB connection retry + wait helper
// - waitForDatabase(maxRetries, delayMs)
// ============================================
const connectWithRetry = (retries = 5) => {
    promisePool.getConnection()
        .then((connection) => {
            console.log('✅ MySQL connected successfully');
            connection.release();
        })
        .catch(err => {
            console.error(`❌ Database connection failed (Attempt ${6 - retries}):`, err.message);
            if (retries > 0) {
                console.log('Retrying in 10 seconds...');
                setTimeout(() => connectWithRetry(retries - 1), 10000);
            } else {
                console.error('Please check environment variables or Aiven network settings.');
            }
        });
};

connectWithRetry();

const waitForDatabase = async (maxRetries = 40, delayMs = 3000) => {
    for (let i = 0; i < maxRetries; i++) {
        try {
            const connection = await promisePool.getConnection();
            connection.release();
            return; // successful
        } catch (err) {
            console.log(`⏳ Waiting for database to wake up... (Attempt ${i + 1}/${maxRetries})`);
            await new Promise(resolve => setTimeout(resolve, delayMs));
        }
    }
    throw new Error('Database connection could not be established after waiting.');
};

// ============================================
// Middleware: ensure DB ready for /api routes
// This causes incoming API requests to wait until DB is available.
// ============================================
app.use('/api', async (req, res, next) => {
  try {
    await waitForDatabase(); // defaults: 40 tries * 3s = up to ~120s
    return next();
  } catch (err) {
    console.error('DB not ready for request:', err.message);
    return res.status(503).json({ error: 'Service temporarily unavailable. Please try again in a few seconds.' });
  }
});

// ============================================
// JWT
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
// AUTH ROUTES (no need to await DB here; middleware already ensures readiness)
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

        const [existing] = await promisePool.query(
            'SELECT id FROM users WHERE username = ?',
            [username]
        );

        if (existing.length > 0) {
            return res.status(400).json({ error: 'Username already taken.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await promisePool.query(
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
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required.' });
        }

        const [users] = await promisePool.query(
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
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

// ============================================
// PROFILE ROUTES (Online Data Sync)
// ============================================

// GET PROFILE
app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const [users] = await promisePool.query(
            'SELECT username, profile_pic, bg_image, theme FROM users WHERE id = ?',
            [req.user.userId]
        );
        if (users.length === 0) return res.status(404).json({ error: 'User not found.' });
        res.json(users[0]);
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ error: 'Failed to fetch profile.' });
    }
});

// UPDATE PROFILE
app.put('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const { username, profile_pic, bg_image, theme } = req.body;
        await promisePool.query(
            'UPDATE users SET username = ?, profile_pic = ?, bg_image = ?, theme = ? WHERE id = ?',
            [username, profile_pic || null, bg_image || null, theme || 'default', req.user.userId]
        );
        res.json({ message: 'Profile updated successfully!' });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Failed to update profile.' });
    }
});

// ============================================
// ROLLOVER ROUTES (same as before)
// ============================================
app.get('/api/rollovers', verifyToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const [runs] = await promisePool.query(
            'SELECT * FROM rollovers WHERE user_id = ? ORDER BY created_at DESC',
            [userId]
        );
        for (let run of runs) {
            const [steps] = await promisePool.query(
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

app.post('/api/rollovers', verifyToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { title, target_goal, initial_stake, base_odds } = req.body;
        if (!title || !initial_stake) {
            return res.status(400).json({ error: 'Title and initial stake are required.' });
        }
        const connection = await promisePool.getConnection();
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
            connection.release();
            res.status(201).json({ message: 'Rollover run created successfully!', runId });
        } catch (error) {
            await connection.rollback();
            connection.release();
            throw error;
        }
    } catch (error) {
        console.error('Error creating rollover:', error);
        res.status(500).json({ error: 'Failed to create rollover run.' });
    }
});

app.put('/api/bets/:id', verifyToken, async (req, res) => {
    try {
        const betId = req.params.id;
        const { status } = req.body;
        const userId = req.user.userId;
        const [check] = await promisePool.query(
            `SELECT s.*, r.user_id 
            FROM bet_steps s
            JOIN rollovers r ON s.rollover_id = r.id
            WHERE s.id = ? AND r.user_id = ?`,
            [betId, userId]
        );
        if (check.length === 0) {
            return res.status(404).json({ error: 'Bet not found.' });
        }
        await promisePool.query(
            'UPDATE bet_steps SET status = ? WHERE id = ?',
            [status, betId]
        );
        if (status === 'loss') {
            await promisePool.query(
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

// HEALTH & TEST
app.get('/api/health', async (req, res) => {
    try {
        const [result] = await promisePool.query('SELECT 1 as connected, NOW() as time');
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

app.get('/api/test', (req, res) => {
    res.json({
        message: 'MxRollover API is running!',
        endpoints: [
            'POST /api/auth/register',
            'POST /api/auth/login',
            'GET /api/user/profile',
            'PUT /api/user/profile',
            'GET /api/rollovers',
            'POST /api/rollovers',
            'PUT /api/bets/:id',
            'GET /api/health',
            'GET /api/test'
        ]
    });
});

// ERROR HANDLER
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error.' });
});

// START SERVER and increase timeout so cold starts aren't cut off
const server = app.listen(PORT, () => {
    console.log(`🚀 MxRollover Backend running on port ${PORT}`);
});

// Allow long requests (set to 3 minutes). Set to 0 for no timeout (use carefully).
server.setTimeout(180000); // 180 seconds