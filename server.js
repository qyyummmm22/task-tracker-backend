// server.js
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE || 'task_tracker_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// --- Authentication & Authorization Middleware (remains the same) ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ message: 'Authentication token required.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token.' });
        }
        req.user = user; // IMPORTANT: req.user now contains { id, username, role }
        next();
    });
};

const authorizeRoles = (roles) => {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Access denied: Insufficient permissions.' });
        }
        next();
    };
};

// --- User Authentication Routes (remains the same) ---
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }
    if (role && !['admin', 'staff'].includes(role)) {
        return res.status(400).json({ message: 'Invalid role specified.' });
    }

    try {
        console.log('Register attempt for username:', username); // Debug log 1

        // Check if user already exists
        console.log('Querying existing users...'); // Debug log 2
        const [existingUsers] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
        console.log('Existing users query complete.'); // Debug log 3

        if (existingUsers.length > 0) {
            return res.status(409).json({ message: 'Username already exists.' });
        }

        // Hash password
        console.log('Hashing password...'); // Debug log 4
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        console.log('Password hashed.'); // Debug log 5

        // Insert new user into database
        const userRole = role || 'staff';
        console.log('Inserting new user:', username, 'with role:', userRole); // Debug log 6
        const [result] = await pool.query(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            [username, hashedPassword, userRole]
        );
        console.log('New user inserted. Insert ID:', result.insertId); // Debug log 7

        // Generate JWT token for immediate login
        console.log('Generating JWT token...'); // Debug log 8
        const token = jwt.sign(
            { id: result.insertId, username, role: userRole },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
        console.log('JWT token generated.'); // Debug log 9

        res.status(201).json({
            message: 'User registered successfully!',
            token,
            user: { id: result.insertId, username, role: userRole }
        });
        console.log('Registration response sent.'); // Debug log 10

    } catch (err) {
        console.error('Error during registration (caught):', err); // Debug log (if error is caught)
        res.status(500).json({ message: 'Server error during registration.', error: err.message });
    }
});

// POST /api/login - User Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        console.log('Login attempt for username:', username); // Debug log 11

        // Find user by username
        console.log('Querying user for login...'); // Debug log 12
        const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        console.log('User query complete.'); // Debug log 13
        const user = users[0];

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        // Compare provided password with hashed password in DB
        console.log('Comparing passwords...'); // Debug log 14
        const isMatch = await bcrypt.compare(password, user.password);
        console.log('Password comparison complete.'); // Debug log 15

        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        // Generate JWT token
        console.log('Generating JWT token for login...'); // Debug log 16
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
        console.log('JWT token generated for login.'); // Debug log 17

        res.status(200).json({
            message: 'Logged in successfully!',
            token,
            user: { id: user.id, username: user.username, role: user.role }
        });
        console.log('Login response sent.'); // Debug log 18

    } catch (err) {
        console.error('Error during login (caught):', err); // Debug log (if error is caught)
        res.status(500).json({ message: 'Server error during login.', error: err.message });
    }
});

// ... (Authentication & Authorization Middleware - remains the same) ...

// --- MODIFIED: Task API Endpoints (NOW WITH OWNERSHIP) ---
// ... (app.get('/api/tasks'), app.post('/api/tasks'), app.put('/api/tasks/:id'), app.delete('/api/tasks/:id')) ...

// --- Start the server ---
app.listen(port, () => {
    console.log(`Backend server listening at http://localhost:${port}`);
});

// --- MODIFIED: Task API Endpoints (NOW WITH OWNERSHIP) ---

// GET tasks for the logged-in user
// GET tasks - Admin sees all, Staff sees their own
// GET tasks - Admin sees all (or specific user's), Staff sees their own
app.get('/api/tasks', authenticateToken, async (req, res) => {
    try {
        let query = 'SELECT t.*, u.username AS owner_username, u.role AS owner_role FROM tasks t JOIN users u ON t.user_id = u.id'; // Default join for task owner info
        let queryParams = [];

        // Check if the authenticated user is an admin
        if (req.user.role === 'admin') {
            const { userId } = req.query; // <--- NEW: Check for userId query parameter

            if (userId) {
                // Admin wants tasks for a specific user
                query += ' WHERE t.user_id = ?'; // <--- Filter by specific user_id
                queryParams.push(userId);
                console.log(`Admin (${req.user.username}) fetching tasks for user ID: ${userId}`);
            } else {
                // Admin wants ALL tasks (default admin view if no userId param)
                console.log(`Admin (${req.user.username}) fetching all tasks.`);
            }
        } else {
            // Staff/regular users: only see their own tasks
            query += ' WHERE t.user_id = ?'; // <--- Filter by authenticated user's ID
            queryParams.push(req.user.id);
            console.log(`Staff user (${req.user.username}) fetching their own tasks.`);
        }

        query += ' ORDER BY t.created_at DESC'; // Always order by creation date

        const [rows] = await pool.query(query, queryParams);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching tasks for user:', req.user?.id, 'Error:', err);
        res.status(500).json({ message: 'Error fetching tasks', error: err.message });
    }
});

// POST a new task for the logged-in user
// POST a new task (staff/admin can create for themselves, admin can assign to others)
app.post('/api/tasks', authenticateToken, authorizeRoles(['admin', 'staff']), async (req, res) => {
    const { title, description, user_id: assignedUserId } = req.body; // <--- MODIFIED: Extract assignedUserId from body
    const loggedInUserId = req.user.id; // Get ID of the user currently logged in
    const loggedInUserRole = req.user.role; // Get role of the user currently logged in

    if (!title) {
        return res.status(400).json({ message: 'Title is required' });
    }

    let taskOwnerId = loggedInUserId; // Default owner is the logged-in user

    // If an admin is logged in AND they provided a user_id in the body,
    // then assign the task to that user_id.
    if (loggedInUserRole === 'admin' && assignedUserId) {
        // Optional: You might want to validate if assignedUserId actually exists in your users table
        // For now, we'll trust the ID passed by admin
        taskOwnerId = assignedUserId;
        console.log(`Admin (${req.user.username}) adding task for user ID: ${taskOwnerId}`);
    } else {
        console.log(`User (${req.user.username}) adding task for themselves.`);
    }

    try {
        // Insert task with the determined taskOwnerId
        const [result] = await pool.query(
            'INSERT INTO tasks (title, description, user_id) VALUES (?, ?, ?)',
            [title, description, taskOwnerId] // <--- MODIFIED to use taskOwnerId
        );
        res.status(201).json({
            id: result.insertId,
            title,
            description,
            completed: false,
            created_at: new Date().toISOString(),
            user_id: taskOwnerId // <--- Include the correct owner ID in response
        });
    } catch (err) {
        console.error('Error adding task:', err);
        res.status(500).json({ message: 'Error adding task', error: err.message });
    }
});

// PUT (update) a task for the logged-in user (ensure ownership)
app.put('/api/tasks/:id', authenticateToken, authorizeRoles(['admin', 'staff']), async (req, res) => {
    const { id } = req.params;
    const { title, description, completed } = req.body;
    const userId = req.user.id; // <--- NEW: Get user ID from authenticated token

    let updateFields = [];
    let queryParams = [];

    if (title !== undefined) {
        updateFields.push('title = ?');
        queryParams.push(title);
    }
    if (description !== undefined) {
        updateFields.push('description = ?');
        queryParams.push(description);
    }
    if (completed !== undefined) {
        updateFields.push('completed = ?');
        queryParams.push(completed);
    }

    if (updateFields.length === 0) {
        return res.status(400).json({ message: 'No valid fields to update.' });
    }

    // Add user_id to the WHERE clause to ensure ownership
    try {
        const [result] = await pool.query(
            `UPDATE tasks SET ${updateFields.join(', ')} WHERE id = ? AND user_id = ?`, // <--- MODIFIED
            [...queryParams, id, userId] // <--- MODIFIED
        );

        if (result.affectedRows === 0) {
            // If affectedRows is 0, it means task was not found OR not owned by the user
            const [taskCheck] = await pool.query('SELECT id FROM tasks WHERE id = ?', [id]);
            if (taskCheck.length === 0) {
                return res.status(404).json({ message: 'Task not found.' });
            } else {
                return res.status(403).json({ message: 'Access denied: You do not own this task.' }); // <--- More specific error
            }
        }
        const [updatedTaskRows] = await pool.query('SELECT * FROM tasks WHERE id = ?', [id]);
        res.json(updatedTaskRows[0]);
    } catch (err) {
        console.error('Error updating task:', err);
        res.status(500).json({ message: 'Error updating task', error: err.message });
    }
});

// DELETE a task (only for admin users, and ensure ownership)
app.delete('/api/tasks/:id', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id; // <--- NEW: Get user ID from authenticated token

    try {
        // Delete task where ID matches AND user_id matches
        const [result] = await pool.query('DELETE FROM tasks WHERE id = ? AND user_id = ?', [id, userId]); // <--- MODIFIED

        if (result.affectedRows === 0) {
            const [taskCheck] = await pool.query('SELECT id FROM tasks WHERE id = ?', [id]);
            if (taskCheck.length === 0) {
                return res.status(404).json({ message: 'Task not found.' });
            } else {
                return res.status(403).json({ message: 'Access denied: You do not own this task.' });
            }
        }
        res.status(204).send();
    } catch (err) {
        console.error('Error deleting task:', err);
        res.status(500).json({ message: 'Error deleting task', error: err.message });
    }
});

// --- Start the server ---
app.listen(port, () => {
    console.log(`Backend server listening at http://localhost:${port}`);
});

// --- NEW: GET /api/users - Get All Users (Admin Only) ---
app.get('/api/users', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
    try {
        const [users] = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC');
        res.json(users);
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ message: 'Error fetching users', error: err.message });
    }
});