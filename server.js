const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-secret-key-change-this-in-production';

// Database connection
const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'twitter_clone'
};

let db;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadPath = file.fieldname === 'video' ? 'uploads/videos/' : 'uploads/images/';
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB limit
    },
    fileFilter: function (req, file, cb) {
        if (file.fieldname === 'image') {
            if (file.mimetype.startsWith('image/')) {
                cb(null, true);
            } else {
                cb(new Error('Only image files are allowed for image uploads'));
            }
        } else if (file.fieldname === 'video') {
            if (file.mimetype.startsWith('video/')) {
                cb(null, true);
            } else {
                cb(new Error('Only video files are allowed for video uploads'));
            }
        } else {
            cb(null, true);
        }
    }
});

// Auth middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Database initialization
async function initDatabase() {
    try {
        // Connect without database first
        const connection = await mysql.createConnection({
            host: dbConfig.host,
            user: dbConfig.user,
            password: dbConfig.password
        });

        // Create database if it doesn't exist
        await connection.execute(`CREATE DATABASE IF NOT EXISTS ${dbConfig.database}`);
        await connection.end();

        // Connect to the database
        db = await mysql.createConnection(dbConfig);
        console.log('Connected to MySQL database');

        // Create tables
        await createTables();
    } catch (error) {
        console.error('Database connection failed:', error);
    }
}

async function createTables() {
    try {
        // Users table
        await db.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                full_name VARCHAR(100),
                bio TEXT,
                profile_image VARCHAR(255),
                followers_count INT DEFAULT 0,
                following_count INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Tweets table
        await db.execute(`
            CREATE TABLE IF NOT EXISTS tweets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                content TEXT,
                image_url VARCHAR(255),
                video_url VARCHAR(255),
                likes_count INT DEFAULT 0,
                retweets_count INT DEFAULT 0,
                comments_count INT DEFAULT 0,
                is_retweet BOOLEAN DEFAULT FALSE,
                original_tweet_id INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (original_tweet_id) REFERENCES tweets(id) ON DELETE CASCADE
            )
        `);

        // Likes table
        await db.execute(`
            CREATE TABLE IF NOT EXISTS likes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                tweet_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_like (user_id, tweet_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (tweet_id) REFERENCES tweets(id) ON DELETE CASCADE
            )
        `);

        // Comments table
        await db.execute(`
            CREATE TABLE IF NOT EXISTS comments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                tweet_id INT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (tweet_id) REFERENCES tweets(id) ON DELETE CASCADE
            )
        `);

        // Follows table
        await db.execute(`
            CREATE TABLE IF NOT EXISTS follows (
                id INT AUTO_INCREMENT PRIMARY KEY,
                follower_id INT NOT NULL,
                following_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_follow (follower_id, following_id),
                FOREIGN KEY (follower_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (following_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        console.log('All tables created successfully');
    } catch (error) {
        console.error('Error creating tables:', error);
    }
}

// Routes

// Serve main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// User Registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, full_name } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password are required' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user
        const [result] = await db.execute(
            'INSERT INTO users (username, email, password, full_name) VALUES (?, ?, ?, ?)',
            [username, email, hashedPassword, full_name || username]
        );

        // Generate token
        const token = jwt.sign({ id: result.insertId, username }, JWT_SECRET);

        res.json({
            message: 'User created successfully',
            token,
            user: { id: result.insertId, username, email, full_name: full_name || username }
        });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ error: 'Username or email already exists' });
        } else {
            res.status(500).json({ error: 'Server error' });
        }
    }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const [users] = await db.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            [username, username]
        );

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];
        const isValidPassword = await bcrypt.compare(password, user.password);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                full_name: user.full_name,
                bio: user.bio,
                profile_image: user.profile_image
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const [users] = await db.execute(
            'SELECT id, username, email, full_name, bio, profile_image, followers_count, following_count FROM users WHERE id = ?',
            [req.user.id]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(users[0]);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Create tweet
app.post('/api/tweets', authenticateToken, upload.fields([
    { name: 'image', maxCount: 1 },
    { name: 'video', maxCount: 1 }
]), async (req, res) => {
    try {
        const { content } = req.body;
        const image_url = req.files?.image ? `/uploads/images/${req.files.image[0].filename}` : null;
        const video_url = req.files?.video ? `/uploads/videos/${req.files.video[0].filename}` : null;

        if (!content && !image_url && !video_url) {
            return res.status(400).json({ error: 'Tweet must have content, image, or video' });
        }

        const [result] = await db.execute(
            'INSERT INTO tweets (user_id, content, image_url, video_url) VALUES (?, ?, ?, ?)',
            [req.user.id, content, image_url, video_url]
        );

        // Get the created tweet with user info
        const [tweets] = await db.execute(`
            SELECT t.*, u.username, u.full_name, u.profile_image 
            FROM tweets t 
            JOIN users u ON t.user_id = u.id 
            WHERE t.id = ?
        `, [result.insertId]);

        res.json(tweets[0]);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get timeline tweets
app.get('/api/tweets/timeline', authenticateToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;

        const [tweets] = await db.execute(`
            SELECT t.*, u.username, u.full_name, u.profile_image,
                   orig_t.content as original_content,
                   orig_u.username as original_username,
                   orig_u.full_name as original_full_name,
                   EXISTS(SELECT 1 FROM likes l WHERE l.tweet_id = t.id AND l.user_id = ?) as user_liked
            FROM tweets t
            JOIN users u ON t.user_id = u.id
            LEFT JOIN tweets orig_t ON t.original_tweet_id = orig_t.id
            LEFT JOIN users orig_u ON orig_t.user_id = orig_u.id
            WHERE t.user_id = ? OR t.user_id IN (
                SELECT following_id FROM follows WHERE follower_id = ?
            )
            ORDER BY t.created_at DESC
            LIMIT ? OFFSET ?
        `, [req.user.id, req.user.id, req.user.id, limit, offset]);

        res.json(tweets);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get all tweets (public timeline)
app.get('/api/tweets', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;

        const [tweets] = await db.execute(`
            SELECT t.*, u.username, u.full_name, u.profile_image,
                   orig_t.content as original_content,
                   orig_u.username as original_username,
                   orig_u.full_name as original_full_name
            FROM tweets t
            JOIN users u ON t.user_id = u.id
            LEFT JOIN tweets orig_t ON t.original_tweet_id = orig_t.id
            LEFT JOIN users orig_u ON orig_t.user_id = orig_u.id
            ORDER BY t.created_at DESC
            LIMIT ? OFFSET ?
        `, [limit, offset]);

        res.json(tweets);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Like/Unlike tweet
app.post('/api/tweets/:id/like', authenticateToken, async (req, res) => {
    try {
        const tweetId = req.params.id;

        // Check if already liked
        const [existingLike] = await db.execute(
            'SELECT * FROM likes WHERE user_id = ? AND tweet_id = ?',
            [req.user.id, tweetId]
        );

        if (existingLike.length > 0) {
            // Unlike
            await db.execute(
                'DELETE FROM likes WHERE user_id = ? AND tweet_id = ?',
                [req.user.id, tweetId]
            );
            await db.execute(
                'UPDATE tweets SET likes_count = likes_count - 1 WHERE id = ?',
                [tweetId]
            );
            res.json({ message: 'Tweet unliked', liked: false });
        } else {
            // Like
            await db.execute(
                'INSERT INTO likes (user_id, tweet_id) VALUES (?, ?)',
                [req.user.id, tweetId]
            );
            await db.execute(
                'UPDATE tweets SET likes_count = likes_count + 1 WHERE id = ?',
                [tweetId]
            );
            res.json({ message: 'Tweet liked', liked: true });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Retweet
app.post('/api/tweets/:id/retweet', authenticateToken, async (req, res) => {
    try {
        const originalTweetId = req.params.id;

        // Check if already retweeted
        const [existingRetweet] = await db.execute(
            'SELECT * FROM tweets WHERE user_id = ? AND original_tweet_id = ? AND is_retweet = TRUE',
            [req.user.id, originalTweetId]
        );

        if (existingRetweet.length > 0) {
            return res.status(400).json({ error: 'Already retweeted' });
        }

        // Create retweet
        await db.execute(
            'INSERT INTO tweets (user_id, is_retweet, original_tweet_id) VALUES (?, TRUE, ?)',
            [req.user.id, originalTweetId]
        );

        // Update retweet count
        await db.execute(
            'UPDATE tweets SET retweets_count = retweets_count + 1 WHERE id = ?',
            [originalTweetId]
        );

        res.json({ message: 'Tweet retweeted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Add comment
app.post('/api/tweets/:id/comment', authenticateToken, async (req, res) => {
    try {
        const tweetId = req.params.id;
        const { content } = req.body;

        if (!content) {
            return res.status(400).json({ error: 'Comment content is required' });
        }

        const [result] = await db.execute(
            'INSERT INTO comments (user_id, tweet_id, content) VALUES (?, ?, ?)',
            [req.user.id, tweetId, content]
        );

        // Update comments count
        await db.execute(
            'UPDATE tweets SET comments_count = comments_count + 1 WHERE id = ?',
            [tweetId]
        );

        // Get the comment with user info
        const [comments] = await db.execute(`
            SELECT c.*, u.username, u.full_name, u.profile_image 
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.id = ?
        `, [result.insertId]);

        res.json(comments[0]);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get comments for a tweet
app.get('/api/tweets/:id/comments', async (req, res) => {
    try {
        const tweetId = req.params.id;

        const [comments] = await db.execute(`
            SELECT c.*, u.username, u.full_name, u.profile_image 
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.tweet_id = ?
            ORDER BY c.created_at DESC
        `, [tweetId]);

        res.json(comments);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Follow/Unfollow user
app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
    try {
        const targetUserId = req.params.id;

        if (targetUserId == req.user.id) {
            return res.status(400).json({ error: 'Cannot follow yourself' });
        }

        // Check if already following
        const [existingFollow] = await db.execute(
            'SELECT * FROM follows WHERE follower_id = ? AND following_id = ?',
            [req.user.id, targetUserId]
        );

        if (existingFollow.length > 0) {
            // Unfollow
            await db.execute(
                'DELETE FROM follows WHERE follower_id = ? AND following_id = ?',
                [req.user.id, targetUserId]
            );
            // Update counts
            await db.execute(
                'UPDATE users SET following_count = following_count - 1 WHERE id = ?',
                [req.user.id]
            );
            await db.execute(
                'UPDATE users SET followers_count = followers_count - 1 WHERE id = ?',
                [targetUserId]
            );
            res.json({ message: 'Unfollowed successfully', following: false });
        } else {
            // Follow
            await db.execute(
                'INSERT INTO follows (follower_id, following_id) VALUES (?, ?)',
                [req.user.id, targetUserId]
            );
            // Update counts
            await db.execute(
                'UPDATE users SET following_count = following_count + 1 WHERE id = ?',
                [req.user.id]
            );
            await db.execute(
                'UPDATE users SET followers_count = followers_count + 1 WHERE id = ?',
                [targetUserId]
            );
            res.json({ message: 'Followed successfully', following: true });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get user profile
app.get('/api/users/:username', async (req, res) => {
    try {
        const username = req.params.username;

        const [users] = await db.execute(
            'SELECT id, username, full_name, bio, profile_image, followers_count, following_count, created_at FROM users WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = users[0];

        // Get user's tweets
        const [tweets] = await db.execute(`
            SELECT t.*, u.username, u.full_name, u.profile_image,
                   orig_t.content as original_content,
                   orig_u.username as original_username,
                   orig_u.full_name as original_full_name
            FROM tweets t
            JOIN users u ON t.user_id = u.id
            LEFT JOIN tweets orig_t ON t.original_tweet_id = orig_t.id
            LEFT JOIN users orig_u ON orig_t.user_id = orig_u.id
            WHERE t.user_id = ?
            ORDER BY t.created_at DESC
        `, [user.id]);

        res.json({ user, tweets });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Search users and tweets
app.get('/api/search', async (req, res) => {
    try {
        const query = req.query.q;
        const type = req.query.type || 'all';

        if (!query) {
            return res.status(400).json({ error: 'Search query is required' });
        }

        let results = {};

        if (type === 'users' || type === 'all') {
            const [users] = await db.execute(`
                SELECT id, username, full_name, bio, profile_image, followers_count, following_count
                FROM users 
                WHERE username LIKE ? OR full_name LIKE ?
                LIMIT 20
            `, [`%${query}%`, `%${query}%`]);
            results.users = users;
        }

        if (type === 'tweets' || type === 'all') {
            const [tweets] = await db.execute(`
                SELECT t.*, u.username, u.full_name, u.profile_image
                FROM tweets t
                JOIN users u ON t.user_id = u.id
                WHERE t.content LIKE ? AND t.is_retweet = FALSE
                ORDER BY t.created_at DESC
                LIMIT 20
            `, [`%${query}%`]);
            results.tweets = tweets;
        }

        res.json(results);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Update profile
app.put('/api/profile', authenticateToken, upload.single('profile_image'), async (req, res) => {
    try {
        const { full_name, bio } = req.body;
        const profile_image = req.file ? `/uploads/images/${req.file.filename}` : null;

        let updateQuery = 'UPDATE users SET ';
        let updateValues = [];
        let updates = [];

        if (full_name !== undefined) {
            updates.push('full_name = ?');
            updateValues.push(full_name);
        }
        if (bio !== undefined) {
            updates.push('bio = ?');
            updateValues.push(bio);
        }
        if (profile_image) {
            updates.push('profile_image = ?');
            updateValues.push(profile_image);
        }

        if (updates.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }

        updateQuery += updates.join(', ') + ' WHERE id = ?';
        updateValues.push(req.user.id);

        await db.execute(updateQuery, updateValues);

        // Get updated user
        const [users] = await db.execute(
            'SELECT id, username, email, full_name, bio, profile_image, followers_count, following_count FROM users WHERE id = ?',
            [req.user.id]
        );

        res.json(users[0]);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Initialize database and start server
initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
});
