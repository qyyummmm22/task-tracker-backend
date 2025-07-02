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

// --- NEW: DELETE /api/users/:id - Delete a User (Admin Only) ---
app.delete('/api/users/:id', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
    const { id } = req.params; // ID of the user to be deleted
    const loggedInUserId = req.user.id; // ID of the admin performing the delete

    // IMPORTANT: Prevent admin from deleting themselves through this endpoint
    if (parseInt(id) === loggedInUserId) {
        return res.status(403).json({ message: 'Forbidden: You cannot delete your own account here.' });
    }

    try {
        const [result] = await pool.query('DELETE FROM users WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }
        console.log(`User ID ${id} deleted successfully by Admin ${req.user.username}`);
        res.status(204).send(); // 204 No Content for successful deletion
    } catch (err) {
        console.error('Error deleting user:', err);
        res.status(500).json({ message: 'Server error during user deletion.', error: err.message });
    }
});

// --- NEW: PUT /api/users/:id/role - Update User Role (Admin Only) ---
app.put('/api/users/:id/role', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
    const { id } = req.params; // ID of the user whose role is being changed
    const { newRole } = req.body; // The new role ('admin' or 'staff')

    // Basic validation for newRole
    if (!newRole || !['admin', 'staff'].includes(newRole.toLowerCase())) {
        return res.status(400).json({ message: 'Invalid role provided. Must be "admin" or "staff".' });
    }

    // Prevent admin from changing their own role (or demoting themselves)
    // A more robust check might ensure at least one admin remains.
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

// --- NEW: PUT /api/users/:id/reset-password - Reset User Password (Admin Only) ---
// --- MODIFIED: PUT /api/users/:id/reset-password - Manual Reset Password (Admin Only) ---
app.put('/api/users/:id/reset-password', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
    const { id } = req.params; // ID of the user whose password is being reset
    const { newPassword } = req.body; // <--- NEW: Expect newPassword from request body

    // Basic validation for newPassword
    if (!newPassword || newPassword.length < 6) { // Example: Minimum 6 characters
        return res.status(400).json({ message: 'New password is required and must be at least 6 characters.' });
    }

    // Prevent admin from resetting their own password through this interface
    if (parseInt(id) === req.user.id) {
        return res.status(403).json({ message: 'Forbidden: You cannot reset your own password here.' });
    }

    try {
        // 1. Hash the provided new password
        const salt = await bcrypt.genSalt(10);
        const hashedNewPassword = await bcrypt.hash(newPassword, salt);

        // 2. Update the user's password in the database
        const [result] = await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }
        // console.log(`Admin ${req.user.username} reset password for user ID ${id}.`); // No longer logging plain password
        console.log(`Admin ${req.user.username} reset password for user ID ${id}.`);
        res.status(200).json({ message: 'Password reset successfully.' }); // <--- No longer returning new_password
    } catch (err) {
        console.error('Error resetting user password:', err);
        res.status(500).json({ message: 'Server error resetting password.', error: err.message });
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
// GET tasks - Admin sees all (or specific user's), Staff sees their own, now with filters
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
        let whereClauses = []; // <--- NEW: Array to hold dynamic WHERE clauses

        // --- User-specific filtering (remains at the start of WHERE clauses) ---
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

        // --- NEW: Filter parameters from query string (req.query) ---
        const { search, completed, priority, startDate, endDate } = req.query;

        // Search by title or description
        if (search) {
            whereClauses.push('(t.title LIKE ? OR t.description LIKE ?)');
            queryParams.push(`%${search}%`, `%${search}%`);
        }

        // Filter by completion status
        if (completed !== undefined) { // Check if 'completed' param exists
            // Convert string 'true'/'false' to boolean 1/0 for MySQL
            const completedValue = (completed === 'true' || completed === '1') ? 1 : 0;
            whereClauses.push('t.completed = ?');
            queryParams.push(completedValue);
        }

        // Filter by priority
        if (priority && ['low', 'medium', 'high'].includes(priority.toLowerCase())) {
            whereClauses.push('t.priority = ?');
            queryParams.push(priority.toLowerCase());
        }

        // Filter by due date range (e.g., tasks due within a period)
        if (startDate) {
            // Ensure startDate is a valid date string for MySQL
            whereClauses.push('t.due_date >= ?');
            queryParams.push(startDate); // Frontend should send YYYY-MM-DD or YYYY-MM-DD HH:MM:SS
        }
        if (endDate) {
            whereClauses.push('t.due_date <= ?');
            queryParams.push(endDate); // Frontend should send YYYY-MM-DD or YYYY-MM-DD HH:MM:SS
        }

        // --- Construct the final WHERE clause ---
        if (whereClauses.length > 0) {
            query += ' WHERE ' + whereClauses.join(' AND ');
        }

        // --- Add ORDER BY clause ---
        query += ' ORDER BY t.created_at DESC';

        const [rows] = await pool.query(query, queryParams);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching tasks with filters:', req.user?.id, 'Error:', err); // Updated log
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
            'INSERT INTO tasks (title, description, user_id, added_by_user_id, due_date, priority) VALUES (?, ?, ?, ?, ?, ?)', // <--- MODIFIED
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
            due_date: due_date, // <--- Add to response
            priority: priority
        });
    } catch (err) {
        console.error('Error adding task:', err);
        res.status(500).json({ message: 'Error adding task', error: err.message });
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
            fs.unlinkSync(req.file.path); // Use fs.unlinkSync
            return res.status(404).json({ message: 'Task not found.' });
        }

        // Authorization check: Only owner or admin can upload/change document for a task
        if (task.user_id !== userId && userRole !== 'admin') {
            // Not owner and not admin, so delete file and deny access
            fs.unlinkSync(req.file.path); // Use fs.unlinkSync
            return res.status(403).json({ message: 'Access denied: You do not have permission to upload for this task.' });
        }

        // If an old document exists for this task, delete it first
        if (task.document_path) {
            try {
                const oldFilePath = `uploads/${task.document_path}`;
                if (fs.existsSync(oldFilePath)) {
                    fs.unlinkSync(oldFilePath); // Delete old file
                    console.log(`Old document for task ${taskId} deleted: ${task.document_path}`);
                }
            } catch (unlinkErr) {
                console.warn(`Could not delete old document for task ${taskId}: ${unlinkErr.message}`);
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
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ message: 'Server error during PDF upload.', error: err.message });
    }
});

// PUT (update) a task for the logged-in user (ensure ownership)
app.put('/api/tasks/:id', authenticateToken, authorizeRoles(['admin', 'staff']), async (req, res) => {
    const { id } = req.params;
    const { title, description, completed, due_date, priority } = req.body;
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

    if (due_date !== undefined) {
        updateFields.push('due_date = ?');
        queryParams.push(due_date);
    }
    
    if (priority !== undefined) {
        updateFields.push('priority = ?');
        queryParams.push(priority);
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