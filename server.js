// server.js
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
require('dotenv').config(); // <--- ADD THIS LINE AT THE VERY TOP

const app = express();
const port = 3000;

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- MySQL Database Connection Pool ---
const pool = mysql.createPool({
    // Use process.env to access the variables from .env file
    host: process.env.DB_HOST || 'localhost', // Default to localhost if not set
    user: process.env.DB_USER, // <--- NOW USING ENVIRONMENT VARIABLE
    password: process.env.DB_PASSWORD, // <--- NOW USING ENVIRONMENT VARIABLE
    database: process.env.DB_DATABASE || 'task_tracker_db', // Default if not set
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ... (rest of your API endpoints remain the same) ...

app.listen(port, () => {
    console.log(`Backend server listening at http://localhost:${port}`);
});

// --- API Endpoints ---

// GET all tasks
app.get('/api/tasks', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM tasks ORDER BY created_at DESC');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching tasks:', err);
        res.status(500).json({ message: 'Error fetching tasks' });
    }
});

// POST a new task
app.post('/api/tasks', async (req, res) => {
    const { title, description } = req.body;
    if (!title) {
        return res.status(400).json({ message: 'Title is required' });
    }
    try {
        const [result] = await pool.query('INSERT INTO tasks (title, description) VALUES (?, ?)', [title, description]);
        res.status(201).json({ id: result.insertId, title, description, completed: false });
    } catch (err) {
        console.error('Error adding task:', err);
        res.status(500).json({ message: 'Error adding task' });
    }
});

// PUT (update) a task
app.put('/api/tasks/:id', async (req, res) => {
    const { id } = req.params;
    const { title, description, completed } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE tasks SET title = ?, description = ?, completed = ? WHERE id = ?',
            [title, description, completed, id]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Task not found' });
        }
        res.json({ id, title, description, completed });
    } catch (err) {
        console.error('Error updating task:', err);
        res.status(500).json({ message: 'Error updating task' });
    }
});

// DELETE a task
app.delete('/api/tasks/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM tasks WHERE id = ?', [id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Task not found' });
        }
        res.status(204).send(); // No content to send back on successful deletion
    } catch (err) {
        console.error('Error deleting task:', err);
        res.status(500).json({ message: 'Error deleting task' });
    }
});

app.listen(port, () => {
    console.log(`Backend server listening at http://localhost:${port}`);
});