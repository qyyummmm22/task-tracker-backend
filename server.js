// server.js
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer'); // NEW: Multer for file uploads
const fs = require('fs'); // NEW: Node.js File System module for deleting files

const app = express();
const port = 3000;

const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

// --- Multer Storage Configuration (THIS COMES FIRST) ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'uploads/';
        // Ensure the uploads directory exists
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir); // Store files in the 'uploads/' directory
    },
    filename: function (req, file, cb) {
        // Create a unique filename: fieldname-timestamp.ext
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const fileExtension = file.originalname.split('.').pop();
        // It's good practice to sanitize filename for security, but for portfolio, this is basic.
        cb(null, file.fieldname + '-' + uniqueSuffix + '.' + fileExtension);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5MB
    fileFilter: (req, file, cb) => {
        // Allow only PDF files
        if (file.mimetype === 'application/pdf') {
            cb(null, true);
        } else {
            cb(new Error('Only PDF files are allowed!'), false);
        }
    }
});


const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE || 'task_tracker_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// --- Authentication & Authorization Middleware ---
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
        req.user = user;
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

// --- User Authentication Routes ---
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }
    if (role && !['admin', 'staff'].includes(role)) {
        return res.status(400).json({ message: 'Invalid role specified.' });
    }

    try {
        const [existingUsers] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
        if (existingUsers.length > 0) {
            return res.status(409).json({ message: 'Username already exists.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const userRole = role || 'staff';
        const [result] = await pool.query(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            [username, hashedPassword, userRole]
        );

        const token = jwt.sign(
            { id: result.insertId, username, role: userRole },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(201).json({
            message: 'User registered successfully!',
            token,
            user: { id: result.insertId, username, role: userRole }
        });

    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).json({ message: 'Server error during registration.', error: err.message });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        const user = users[0];

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            message: 'Logged in successfully!',
            token,
            user: { id: user.id, username: user.username, role: user.role }
        });

    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ message: 'Server error during login.', error: err.message });
    }
});

// --- NEW: GET /api/users - Get All Users (Admin Only) ---
app.get('/api/users', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
    try {
        const [users] = await pool.query(`
            SELECT
                u.id,
                u.username,
                u.role,
                u.created_at,
                COUNT(t.id) AS task_count
            FROM
                users u
            LEFT JOIN
                tasks t ON u.id = t.user_id
            GROUP BY
                u.id, u.username, u.role, u.created_at
            ORDER BY
                u.created_at DESC
        `);
        res.json(users);
    } catch (err) {
        console.error('Error fetching users with task count:', err);
        res.status(500).json({ message: 'Error fetching users', error: err.message });
    }
});


// --- MODIFIED: Task API Endpoints ---

// --- NEW: GET /api/tasks/:id/download-pdf - Endpoint to serve the PDF file ---
app.get('/api/tasks/:id/download-pdf', authenticateToken, async (req, res) => {
    const { id: taskId } = req.params; // ID of the task
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        const [tasks] = await pool.query('SELECT user_id, document_path FROM tasks WHERE id = ?', [taskId]);
        const task = tasks[0];

        // 1. Check if task exists and has a document
        if (!task || !task.document_path) {
            return res.status(404).json({ message: 'Document not found for this task.' });
        }

        // 2. Authorization check: Only owner or admin can download
        if (task.user_id !== userId && userRole !== 'admin') {
            return res.status(403).json({ message: 'Access denied: You do not have permission to download this document.' });
        }

        // 3. Construct file path and check if file exists on disk
        const filePath = `uploads/${task.document_path}`;
        if (!fs.existsSync(filePath)) { // Use fs.existsSync to check file presence
            console.error(`File not found on server for task ${taskId}: ${filePath}`);
            return res.status(404).json({ message: 'File not found on server.' });
        }

        // 4. Serve the file for download
        res.download(filePath, task.document_path); // 'res.download' sends file and sets headers
        console.log(`Document for task ${taskId} downloaded by user ${req.user.username}: ${task.document_path}`);

    } catch (err) {
        console.error('Error downloading PDF for task:', taskId, err);
        res.status(500).json({ message: 'Server error during PDF download.', error: err.message });
    }
});

// GET tasks - Admin sees all (or specific user's), Staff sees their own
app.get('/api/tasks', authenticateToken, async (req, res) => {
    try {
        let query;
        let queryParams = [];

        query = `
            SELECT
                t.*,
                u.username AS owner_username,
                u.role AS owner_role,
                adder.username AS added_by_username
            FROM
                tasks t
            JOIN
                users u ON t.user_id = u.id
            LEFT JOIN
                users adder ON t.added_by_user_id = adder.id
        `;

        if (req.user.role === 'admin') {
            const { userId } = req.query;

            if (userId) {
                query += ' WHERE t.user_id = ?';
                queryParams.push(userId);
            }
        } else {
            query += ' WHERE t.user_id = ?';
            queryParams.push(req.user.id);
        }

        query += ' ORDER BY t.created_at DESC';

        const [rows] = await pool.query(query, queryParams);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching tasks for user:', req.user?.id, 'Error:', err);
        res.status(500).json({ message: 'Error fetching tasks', error: err.message });
    }
});

// POST a new task (staff/admin can create for themselves, admin can assign to others)
app.post('/api/tasks', authenticateToken, authorizeRoles(['admin', 'staff']), async (req, res) => {
    const { title, description, user_id: assignedUserId } = req.body;
    const loggedInUserId = req.user.id;
    const loggedInUserRole = req.user.role;
    const loggedInUsername = req.user.username;

    if (!title) {
        return res.status(400).json({ message: 'Title is required' });
    }

    let taskOwnerId = loggedInUserId;
    let taskAddedById = loggedInUserId;

    if (loggedInUserRole === 'admin' && assignedUserId && assignedUserId !== loggedInUserId) {
        taskOwnerId = assignedUserId;
    }

    try {
        const [result] = await pool.query(
            'INSERT INTO tasks (title, description, user_id, added_by_user_id) VALUES (?, ?, ?, ?)',
            [title, description, taskOwnerId, taskAddedById]
        );
        res.status(201).json({
            id: result.insertId,
            title,
            description,
            completed: false,
            created_at: new Date().toISOString(),
            user_id: taskOwnerId,
            added_by_user_id: taskAddedById,
            added_by_username: loggedInUsername
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
    const userId = req.user.id; // The ID of the currently logged-in user
    const userRole = req.user.role; // <--- NEW: Get the role of the logged-in user

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

    let query; // <--- NEW
    let whereClause; // <--- NEW

    // --- MODIFIED LOGIC HERE ---
    if (userRole === 'admin') {
        // Admin can update any task by its ID
        whereClause = 'WHERE id = ?';
        queryParams.push(id); // Add task ID to params
        console.log('Admin user updating any task.');
    } else {
        // Staff users can only update tasks they own
        whereClause = 'WHERE id = ? AND user_id = ?';
        queryParams.push(id, userId); // Add task ID and user ID to params
        console.log('Staff user updating their own task.');
    }

    query = `UPDATE tasks SET ${updateFields.join(', ')} ${whereClause}`; // <--- Construct full query

    try {
        const [result] = await pool.query(query, queryParams); // <--- Use dynamic query and params

        if (result.affectedRows === 0) {
            // Determine if 404 (not found at all) or 403 (not owned / unauthorized)
            const [taskCheck] = await pool.query('SELECT id FROM tasks WHERE id = ?', [id]);
            if (taskCheck.length === 0) {
                return res.status(404).json({ message: 'Task not found.' });
            } else {
                // This 'else' path implies it was found but not owned (only applies to staff or if admin tried to update non-existent task by owner)
                return res.status(403).json({ message: 'Access denied: You do not own this task, or Admin tried to update a non-existent ID.' });
            }
        }
        // Fetch the updated task to return the most current state from DB
        const [updatedTaskRows] = await pool.query('SELECT * FROM tasks WHERE id = ?', [id]);
        res.json(updatedTaskRows[0]);
    } catch (err) {
        console.error('Error updating task:', err);
        res.status(500).json({ message: 'Error updating task', error: err.message });
    }
});

// DELETE a task (Allow staff to delete their own, admin their own)
app.delete('/api/tasks/:id', authenticateToken, authorizeRoles(['admin', 'staff']), async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    const userRole = req.user.role;

    // console.log(`DELETE attempt for Task ID: ${id} by User ID: ${userId} (Role: ${userRole})`);

    let query;
    let queryParams;

    if (userRole === 'admin') {
        query = 'DELETE FROM tasks WHERE id = ?';
        queryParams = [id];
    } else {
        query = 'DELETE FROM tasks WHERE id = ? AND user_id = ?';
        queryParams = [id, userId];
    }

    try {
        const [result] = await pool.query(query, queryParams);

        // console.log('SQL Query Result for DELETE:', result);
        // console.log('Affected rows:', result.affectedRows);

        if (result.affectedRows === 0) {
            const [taskCheck] = await pool.query('SELECT id FROM tasks WHERE id = ?', [id]);
            if (taskCheck.length === 0) {
                return res.status(404).json({ message: 'Task not found.' });
            } else {
                return res.status(403).json({ message: 'Access denied: You do not own this task, or Admin tried to delete an non-existent ID.' });
            }
        }
        // console.log(`Task ID ${id} deleted successfully by user ${userId}.`);
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