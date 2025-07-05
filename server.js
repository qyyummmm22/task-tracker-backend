// server.js
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer'); // For file uploads
const fs = require('fs'); // Node.js File System module

const app = express();
const port = 3000;

const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

// --- Multer Storage Configuration ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const fileExtension = file.originalname.split('.').pop();
        cb(null, file.fieldname + '-' + uniqueSuffix + '.' + fileExtension);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5MB
    fileFilter: (req, file, cb) => {
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
    queueLimit: 0,
    timezone: 'Z' // Ensure timestamps are in UTC
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

// --- NEW: DELETE /api/users/:id - Delete a User (Admin Only) ---
app.delete('/api/users/:id', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
    const { id } = req.params;
    const loggedInUserId = req.user.id;

    if (parseInt(id) === loggedInUserId) {
        return res.status(403).json({ message: 'Forbidden: You cannot delete your own account here.' });
    }

    try {
        const [result] = await pool.query('DELETE FROM users WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }
        console.log(`User ID ${id} deleted successfully by Admin ${req.user.username}`);
        res.status(204).send();
    } catch (err) {
        console.error('Error deleting user:', err);
        res.status(500).json({ message: 'Server error during user deletion.', error: err.message });
    }
});

// --- NEW: PUT /api/users/:id/role - Update User Role (Admin Only) ---
app.put('/api/users/:id/role', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
    const { id } = req.params;
    const { newRole } = req.body;

    if (!newRole || !['admin', 'staff'].includes(newRole.toLowerCase())) {
        return res.status(400).json({ message: 'Invalid role provided. Must be "admin" or "staff".' });
    }

    if (parseInt(id) === req.user.id) {
        return res.status(403).json({ message: 'Forbidden: You cannot change your own role through this interface.' });
    }

    try {
        const [result] = await pool.query('UPDATE users SET role = ? WHERE id = ?', [newRole.toLowerCase(), id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found or role is already the same.' });
        }
        console.log(`Admin ${req.user.username} changed role of user ID ${id} to ${newRole.toLowerCase()}`);
        res.status(200).json({ message: `User role updated to ${newRole.toLowerCase()}.` });
    } catch (err) {
        console.error('Error updating user role:', err);
        res.status(500).json({ message: 'Server error updating user role.', error: err.message });
    }
});

// --- NEW: PUT /api/users/:id/reset-password - Manual Reset Password (Admin Only) ---
app.put('/api/users/:id/reset-password', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
    const { id } = req.params;
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ message: 'New password is required and must be at least 6 characters.' });
    }

    if (parseInt(id) === req.user.id) {
        return res.status(403).json({ message: 'Forbidden: You cannot reset your own password here.' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedNewPassword = await bcrypt.hash(newPassword, salt);

        const [result] = await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }
        console.log(`Admin ${req.user.username} reset password for user ID ${id}.`);
        res.status(200).json({ message: 'Password reset successfully.' });
    } catch (err) {
        console.error('Error resetting user password:', err);
        res.status(500).json({ message: 'Server error resetting password.', error: err.message });
    }
});

// --- NEW: GET /api/users/me - Get Current User's Profile (Authenticated) ---
app.get('/api/users/me', authenticateToken, async (req, res) => {
    try {
        // req.user contains id, username, role from the JWT payload
        const [users] = await pool.query('SELECT id, username, role, created_at FROM users WHERE id = ?', [req.user.id]);
        const user = users[0];

        if (!user) {
            // This scenario implies a token for a non-existent user, very rare
            return res.status(404).json({ message: 'User not found.' });
        }
        res.json(user);
    } catch (err) {
        console.error('Error fetching current user profile:', err);
        res.status(500).json({ message: 'Server error fetching profile.', error: err.message });
    }
});

// --- NEW: PUT /api/users/me/password - Change Current User's Password (Authenticated) ---
app.put('/api/users/me/password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.id; // The ID of the currently logged-in user

    // Basic validation
    if (!oldPassword || !newPassword) {
        return res.status(400).json({ message: 'Old and new passwords are required.' });
    }
    if (newPassword.length < 6) { // Consistent with registration/reset validation
        return res.status(400).json({ message: 'New password must be at least 6 characters.' });
    }

    try {
        // 1. Fetch user to verify old password
        const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
        const user = users[0];

        if (!user) {
            // User not found (shouldn't happen with authenticated token unless user was deleted)
            return res.status(404).json({ message: 'User not found.' });
        }

        // 2. Compare old password
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Incorrect old password.' });
        }

        // 3. Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedNewPassword = await bcrypt.hash(newPassword, salt);

        // 4. Update password in database
        await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, userId]);

        res.status(200).json({ message: 'Password changed successfully.' });

    } catch (err) {
        console.error('Error changing user password:', err);
        res.status(500).json({ message: 'Server error changing password.', error: err.message });
    }
});

// --- NEW: GET /api/users/me - Get Current User's Profile (Authenticated) ---
app.get('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const [users] = await pool.query('SELECT id, username, role, created_at FROM users WHERE id = ?', [req.user.id]);
        const user = users[0];

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        res.json(user);
    } catch (err) {
        console.error('Error fetching current user profile:', err);
        res.status(500).json({ message: 'Server error fetching profile.', error: err.message });
    }
});

// --- NEW: PUT /api/users/me/password - Change Current User's Password (Authenticated) ---
app.put('/api/users/me/password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.id;

    if (!oldPassword || !newPassword) {
        return res.status(400).json({ message: 'Old and new passwords are required.' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ message: 'New password must be at least 6 characters.' });
    }

    try {
        const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
        const user = users[0];

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Incorrect old password.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedNewPassword = await bcrypt.hash(newPassword, salt);

        await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, userId]);

        res.status(200).json({ message: 'Password changed successfully.' });

    } catch (err) {
        console.error('Error changing user password:', err);
        res.status(500).json({ message: 'Server error changing password.', error: err.message });
    }
});


// --- MODIFIED: Task API Endpoints ---

// --- NEW: GET /api/tasks/:id/download-pdf - Endpoint to serve the PDF file ---
app.get('/api/tasks/:id/download-pdf', authenticateToken, async (req, res) => {
    const { id: taskId } = req.params;
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        const [tasks] = await pool.query('SELECT user_id, document_path FROM tasks WHERE id = ?', [taskId]);
        const task = tasks[0];

        if (!task || !task.document_path) {
            return res.status(404).json({ message: 'Document not found for this task.' });
        }

        if (task.user_id !== userId && userRole !== 'admin') {
            return res.status(403).json({ message: 'Access denied: You do not have permission to download this document.' });
        }

        const filePath = `uploads/${task.document_path}`;
        if (!fs.existsSync(filePath)) {
            console.error(`File not found on server for task ${taskId}: ${filePath}`);
            return res.status(404).json({ message: 'File not found on server.' });
        }

        res.download(filePath, task.document_path);
        console.log(`Document for task ${taskId} downloaded by user ${req.user.username}: ${task.document_path}`);

    } catch (err) {
        console.error('Error downloading PDF for task:', taskId, err);
        res.status(500).json({ message: 'Server error during PDF download.', error: err.message });
    }
});

// GET tasks - Admin sees all (or specific user's), Staff sees their own
app.get('/api/tasks', authenticateToken, async (req, res) => {
    try {
        let query = `
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
        let queryParams = [];
        let whereClauses = [];

        if (req.user.role === 'admin') {
            const { userId } = req.query;
            if (userId) {
                whereClauses.push('t.user_id = ?');
                queryParams.push(userId);
            }
        } else {
            whereClauses.push('t.user_id = ?');
            queryParams.push(req.user.id);
        }

        const { search, completed, priority, startDate, endDate } = req.query;

        if (search) {
            whereClauses.push('(t.title LIKE ? OR t.description LIKE ?)');
            queryParams.push(`%${search}%`, `%${search}%`);
        }

        if (completed !== undefined) {
            const completedValue = (completed === 'true' || completed === '1') ? 1 : 0;
            whereClauses.push('t.completed = ?');
            queryParams.push(completedValue);
        }

        if (priority && ['low', 'medium', 'high'].includes(priority.toLowerCase())) {
            whereClauses.push('t.priority = ?');
            queryParams.push(priority.toLowerCase());
        }

        if (startDate) {
            whereClauses.push('t.due_date >= ?');
            queryParams.push(startDate);
        }
        if (endDate) {
            whereClauses.push('t.due_date <= ?');
            queryParams.push(endDate);
        }

        if (whereClauses.length > 0) {
            query += ' WHERE ' + whereClauses.join(' AND ');
        }

        query += ' ORDER BY t.created_at DESC';

        const [rows] = await pool.query(query, queryParams);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching tasks with filters:', req.user?.id, 'Error:', err);
        res.status(500).json({ message: 'Error fetching tasks', error: err.message });
    }
});

// POST a new task (staff/admin can create for themselves, admin can assign to others)
app.post('/api/tasks', authenticateToken, authorizeRoles(['admin', 'staff']), async (req, res) => {
    const { title, description, user_id: assignedUserId, due_date, priority } = req.body;
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
            'INSERT INTO tasks (title, description, user_id, added_by_user_id, due_date, priority) VALUES (?, ?, ?, ?, ?, ?)',
            [title, description, taskOwnerId, taskAddedById, due_date, priority]
        );
        res.status(201).json({
            id: result.insertId,
            title,
            description,
            completed: false,
            created_at: new Date().toISOString(),
            user_id: taskOwnerId,
            added_by_user_id: taskAddedById,
            added_by_username: loggedInUsername,
            due_date: due_date,
            priority: priority
        });
    } catch (err) {
        console.error('Error adding task:', err);
        res.status(500).json({ message: 'Error adding task', error: err.message });
    }
});

// PUT (update) a task for the logged-in user (ensure ownership)
app.put('/api/tasks/:id', authenticateToken, authorizeRoles(['admin', 'staff']), async (req, res) => {
    const { id } = req.params;
    const { title, description, completed, due_date, priority } = req.body;
    const userId = req.user.id;
    const userRole = req.user.role;

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

    if (due_date !== undefined) {
        updateFields.push('due_date = ?');
        queryParams.push(due_date);
    }
    
    if (priority !== undefined) {
        updateFields.push('priority = ?');
        queryParams.push(priority);
    }

    let query;
    let whereClause;

    if (userRole === 'admin') {
        whereClause = 'WHERE id = ?';
        queryParams.push(id);
    } else {
        whereClause = 'WHERE id = ? AND user_id = ?';
        queryParams.push(id, userId);
    }

    query = `UPDATE tasks SET ${updateFields.join(', ')} ${whereClause}`;

    try {
        const [result] = await pool.query(query, queryParams);

        if (result.affectedRows === 0) {
            const [taskCheck] = await pool.query('SELECT id FROM tasks WHERE id = ?', [id]);
            if (taskCheck.length === 0) {
                return res.status(404).json({ message: 'Task not found.' });
            } else {
                return res.status(403).json({ message: 'Access denied: You do not own this task, or Admin tried to update a non-existent ID.' });
            }
        }
        const [updatedTaskRows] = await pool.query('SELECT * FROM tasks WHERE id = ?', [id]);
        res.json(updatedTaskRows[0]);
    } catch (err) {
        console.error('Error updating task:', err);
        res.status(500).json({ message: 'Error updating task', error: err.message });
    }
});

// --- NEW: POST /api/tasks/:id/upload-pdf - Upload PDF for a Task ---
app.post('/api/tasks/:id/upload-pdf', authenticateToken, authorizeRoles(['admin', 'staff']), upload.single('pdfFile'), async (req, res) => {
    const { id: taskId } = req.params; // ID of the task to attach PDF to
    const userId = req.user.id; // ID of the user performing the upload
    const userRole = req.user.role;

    // Check if a file was actually uploaded
    if (!req.file) {
        return res.status(400).json({ message: 'No PDF file uploaded.' });
    }

    try {
        // First, verify that the task exists and is owned by the user (or user is admin)
        const [tasks] = await pool.query('SELECT user_id, document_path FROM tasks WHERE id = ?', [taskId]);
        const task = tasks[0];

        if (!task) {
            // If task not found, delete the uploaded file
            require('fs').unlinkSync(req.file.path);
            return res.status(404).json({ message: 'Task not found.' });
        }

        // Authorization check: Only owner or admin can upload/change document for a task
        if (task.user_id !== userId && userRole !== 'admin') {
            // Not owner and not admin, so delete file and deny access
            require('fs').unlinkSync(req.file.path);
            return res.status(403).json({ message: 'Access denied: You do not have permission to upload for this task.' });
        }

        // If an old document exists for this task, delete it first
        if (task.document_path) {
            try {
                require('fs').unlinkSync(`uploads/${task.document_path}`); // Delete old file
                console.log(`Old document for task ${taskId} deleted: ${task.document_path}`);
            } catch (unlinkErr) {
                console.warn(`Could not delete old document for task ${taskId}: ${unlinkErr.message}`);
                // Continue even if old file deletion fails (it might not exist, etc.)
            }
        }

        // Update the task in the database with the new document path
        const documentPath = req.file.filename; // Use the filename generated by Multer

        await pool.query('UPDATE tasks SET document_path = ? WHERE id = ?', [documentPath, taskId]);

        res.status(200).json({
            message: 'PDF uploaded successfully!',
            document_path: documentPath // Send back the path so frontend can update
        });

    } catch (err) {
        console.error('Error uploading PDF for task:', taskId, err);
        // If an error occurred after file upload but before DB update, delete the uploaded file
        if (req.file && require('fs').existsSync(req.file.path)) {
            require('fs').unlinkSync(req.file.path);
        }
        res.status(500).json({ message: 'Server error during PDF upload.', error: err.message });
    }
});

// This allows downloading the file from the browser
app.get('/api/tasks/:id/download-pdf', authenticateToken, async (req, res) => {
    const { id: taskId } = req.params;
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        const [tasks] = await pool.query('SELECT user_id, document_path FROM tasks WHERE id = ?', [taskId]);
        const task = tasks[0];

        if (!task || !task.document_path) {
            return res.status(404).json({ message: 'Document not found for this task.' });
        }

        // Authorization check: Only owner or admin can download
        if (task.user_id !== userId && userRole !== 'admin') {
            return res.status(403).json({ message: 'Access denied: You do not have permission to download this document.' });
        }

        const filePath = `uploads/${task.document_path}`;
        if (!require('fs').existsSync(filePath)) {
            return res.status(404).json({ message: 'File not found on server.' });
        }

        res.download(filePath, task.document_path); // Serve the file for download

    } catch (err) {
        console.error('Error downloading PDF for task:', taskId, err);
        res.status(500).json({ message: 'Server error during PDF download.', error: err.message });
    }
});

// DELETE a task (Allow staff to delete their own, admin their own)
app.delete('/api/tasks/:id', authenticateToken, authorizeRoles(['admin', 'staff']), async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    const userRole = req.user.role;

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

        if (result.affectedRows === 0) {
            const [taskCheck] = await pool.query('SELECT id FROM tasks WHERE id = ?', [id]);
            if (taskCheck.length === 0) {
                return res.status(404).json({ message: 'Task not found.' });
            } else {
                return res.status(403).json({ message: 'Access denied: You do not own this task, or Admin tried to delete an non-existent ID.' });
            }
        }
        res.status(204).send();
    } catch (err) {
        console.error('Error deleting task:', err);
        res.status(500).json({ message: 'Error deleting task', error: err.message });
    }
}
);

// GET /api/tasks/:id/comments - Get comments for a specific task
app.get('/api/tasks/:id/comments', authenticateToken, async (req, res) => {
    const { id: taskId } = req.params;
    // No authorization check here if any logged-in user can see comments on tasks they can view.
    // If only task owner/admin can see comments, add task.user_id check here.
    // For simplicity, let's assume if you can see the task, you can see its comments.

    try {
        const [comments] = await pool.query(`
            SELECT
                c.id,
                c.task_id,
                c.user_id,
                c.content,
                c.created_at,
                u.username AS commenter_username,
                u.role AS commenter_role
            FROM
                comments c
            JOIN
                users u ON c.user_id = u.id
            WHERE
                c.task_id = ?
            ORDER BY
                c.created_at ASC
        `, [taskId]);
        res.json(comments);
    } catch (err) {
        console.error('Error fetching comments for task:', taskId, err);
        res.status(500).json({ message: 'Server error fetching comments.', error: err.message });
    }
});

// POST /api/tasks/:id/comments - Add a new comment to a task
app.post('/api/tasks/:id/comments', authenticateToken, authorizeRoles(['admin', 'staff']), async (req, res) => {
    const { id: taskId } = req.params;
    const { content } = req.body;
    const userId = req.user.id; // The ID of the currently logged-in user

    if (!content || content.trim() === '') {
        return res.status(400).json({ message: 'Comment content cannot be empty.' });
    }

    try {
        // Optional: Verify task exists before adding comment
        const [tasks] = await pool.query('SELECT id FROM tasks WHERE id = ?', [taskId]);
        if (tasks.length === 0) {
            return res.status(404).json({ message: 'Task not found.' });
        }

        const [result] = await pool.query(
            'INSERT INTO comments (task_id, user_id, content) VALUES (?, ?, ?)',
            [taskId, userId, content.trim()]
        );

        // Fetch the newly created comment with username for immediate frontend display
        const [newCommentRows] = await pool.query(`
            SELECT
                c.id,
                c.task_id,
                c.user_id,
                c.content,
                c.created_at,
                u.username AS commenter_username,
                u.role AS commenter_role
            FROM
                comments c
            JOIN
                users u ON c.user_id = u.id
            WHERE
                c.id = ?
        `, [result.insertId]);

        res.status(201).json(newCommentRows[0]); // Send back the full new comment object

    } catch (err) {
        console.error('Error adding comment to task:', taskId, err);
        res.status(500).json({ message: 'Server error adding comment.', error: err.message });
    }
});

// --- Start the server ---
app.listen(port, () => {
    console.log(`Backend server listening at http://localhost:${port}`);
});