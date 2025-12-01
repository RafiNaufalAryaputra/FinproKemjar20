const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_production';
const TOKEN_EXPIRY = process.env.TOKEN_EXPIRY || '1h';

const authLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 10,
    message: { message: 'Too many requests, please try again later.' }
});

function generateToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Missing token' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}

const mongoUri = process.env.MONGO_URI || 'mongodb+srv://FinproKemjar20:MbuyMpruy@finproprakkemjar.xzuzsrl.mongodb.net/?appName=FinproPrakKemjar';
const client = new MongoClient(mongoUri);
let usersColl, todosColl, countersColl;

(async () => {
    try {
        await client.connect();
        const db = client.db('FinproKemjar');
        usersColl = db.collection('users');
        todosColl = db.collection('todos');
        countersColl = db.collection('counters');
        console.log('Connected to MongoDB');
    } catch (err) {
        console.error('Failed to connect to MongoDB:', err);
        process.exit(1);
    }
})();

// Register user
app.post('/register', authLimiter, (req, res) => {
    const { username, password } = req.body;
    if (!usersColl || !countersColl) return res.status(503).json({ message: 'Database initializing' });
    if (!username || !password || password.length < 6) return res.status(400).json({ message: 'Invalid username or password (min 6 chars)' });
    (async () => {
        try {
            const existing = await usersColl.findOne({ username });
            if (existing) return res.status(409).json({ message: 'Username already exists' });

            const seqDoc = await countersColl.findOneAndUpdate(
                { _id: 'userid' },
                { $inc: { seq: 1 } },
                { upsert: true, returnDocument: 'after' }
            );
            const newUserId = seqDoc.value.seq;

            const hashed = await bcrypt.hash(password, 10);

            const result = await usersColl.insertOne({ username, password: hashed, userId: newUserId });
            res.json({ message: 'User registered successfully', userId: newUserId });
        } catch (err) {
            console.log(err);
            res.status(500).json({ message: 'Registration failed', error: err.message });
        }
    })();
});

// Login user
app.post('/login', authLimiter, (req, res) => {
    const { username, password } = req.body;
    if (!usersColl) return res.status(503).json({ message: 'Database initializing' });
    (async () => {
        try {
            const user = await usersColl.findOne({ username });
            if (user && await bcrypt.compare(password, user.password)) {
                const payload = { userId: user.userId ?? user._id.toString(), username: user.username };
                const token = generateToken(payload);
                res.json({ message: 'Login successful', token, userId: payload.userId });
            } else {
                res.status(401).json({ message: 'Invalid credentials' });
            }
        } catch (err) {
            console.log(err);
            res.status(500).json({ message: 'Database error' });
        }
    })();
});

// Get todos for a user
app.get('/todos/:userId', authenticateToken, (req, res) => {
    const { userId } = req.params;
    if (!todosColl) return res.status(503).json({ message: 'Database initializing' });
    // Ensure token userId matches requested userId
    if (req.user.userId.toString() !== userId.toString()) return res.status(403).json({ message: 'Forbidden' });
    (async () => {
        try {
            const uid = parseInt(userId, 10);
            const docs = await todosColl.find({ user_id: uid }).toArray();
            const rows = docs.map(d => ({ id: d._id.toString(), content: d.content }));
            res.json(rows);
        } catch (err) {
            console.log(err);
            res.status(500).json({ message: 'Database error' });
        }
    })();
});

// Add todo
app.post('/todos', authenticateToken, (req, res) => {
    const { userId, content } = req.body;
    if (!todosColl) return res.status(503).json({ message: 'Database initializing' });
    if (req.user.userId.toString() !== userId.toString()) return res.status(403).json({ message: 'Forbidden' });
    (async () => {
        try {
            const uid = parseInt(userId, 10);
            const result = await todosColl.insertOne({ user_id: uid, content });
            res.json({ message: 'Todo added', entryId: result.insertedId.toString() });
        } catch (err) {
            console.log(err);
            res.status(500).json({ message: 'Failed to add todo', error: err.message });
        }
    })();
});

// Delete todo
app.delete('/todos/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    if (!todosColl) return res.status(503).json({ message: 'Database initializing' });
    (async () => {
        try {
            // Ensure the todo belongs to the user before deleting
            const doc = await todosColl.findOne({ _id: new ObjectId(id) });
            if (!doc) return res.status(404).json({ message: 'Todo not found' });
            if (doc.user_id.toString() !== req.user.userId.toString()) return res.status(403).json({ message: 'Forbidden' });
            await todosColl.deleteOne({ _id: new ObjectId(id) });
            res.json({ message: 'Todo deleted' });
        } catch (err) {
            console.log(err);
            res.status(500).json({ message: 'Failed to delete todo', error: err.message });
        }
    })();
});

// Change password
app.post('/change-password', authLimiter, authenticateToken, (req, res) => {
    const { userId, currentPassword, newPassword } = req.body;
    if (!usersColl) return res.status(503).json({ message: 'Database initializing' });
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ message: 'New password must be at least 6 characters' });
    if (req.user.userId.toString() !== userId.toString()) return res.status(403).json({ message: 'Forbidden' });
    (async () => {
        try {
            const uid = parseInt(userId, 10);
            const user = await usersColl.findOne({ userId: uid });
            if (!user) return res.status(404).json({ message: 'User not found' });
            const ok = await bcrypt.compare(currentPassword, user.password);
            if (!ok) return res.status(401).json({ message: 'Current password incorrect' });
            const hashed = await bcrypt.hash(newPassword, 10);
            const resu = await usersColl.updateOne({ userId: uid }, { $set: { password: hashed } });
            if (resu.modifiedCount && resu.modifiedCount > 0) {
                res.json({ message: 'Password changed successfully' });
            } else {
                res.status(500).json({ message: 'Failed to change password' });
            }
        } catch (err) {
            console.log(err);
            res.status(500).json({ message: 'Failed to change password', error: err.message });
        }
    })();
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
