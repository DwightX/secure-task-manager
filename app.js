// app.js - Main server file (INTENTIONALLY VULNERABLE)
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const _ = require('lodash');

const app = express();
const PORT = process.env.PORT || 3000;

// VULNERABILITY 1: Hardcoded secret
const SECRET_KEY = "admin123password";

// VULNERABILITY 2: Vulnerable dependency (lodash 4.17.10)
// This version has known security issues

// Database setup
const db = new sqlite3.Database(
    process.env.NODE_ENV === 'test' ? ':memory:' : './tasks.db'
  );
  
// Initialize database tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password TEXT
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        description TEXT,
        completed BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// VULNERABILITY 3: Insecure session configuration
app.use(session({
    secret: SECRET_KEY,
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false,  // Should be true in production with HTTPS
        httpOnly: false,  // Should be true to prevent XSS
        maxAge: 24 * 60 * 60 * 1000  // 24 hours
    }
}));

// Routes

// Home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
// Route to check server health
app.get('/health', (req, res) => {  
    db.get('SELECT 1', (err, row) => {
      if (err) {
        return res.status(500).send(err.message);
      }
      if (!row) {
        return res.status(500).send('Database not reachable');
      }
      res.status(200).send('OK');  // Send 200 only after DB check succeeds
    });
  });
  


// VULNERABILITY 4: SQL Injection in login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // DANGEROUS: Direct string concatenation - SQL injection vulnerability
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    
    db.get(query, (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // VULNERABILITY 5: Plain text password comparison (should use bcrypt)
        if (password === user.password) {
            req.session.userId = user.id;
            req.session.username = user.username;
            res.json({ message: 'Login successful', redirect: '/dashboard' });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// VULNERABILITY 6: No input validation on registration
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    
    // VULNERABILITY 7: Storing plain text passwords
    const query = `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`;
    
    db.run(query, [username, email, password], function(err) {
        if (err) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        
        res.json({ message: 'Registration successful' });
    });
});

// Dashboard - requires authentication (sort of)
app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// VULNERABILITY 8: SQL Injection in task retrieval
app.get('/api/tasks', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const userId = req.session.userId;
    const search = req.query.search || '';
    
    // DANGEROUS: SQL injection through search parameter
    let query = `SELECT * FROM tasks WHERE user_id = ${userId}`;
    if (search) {
        query += ` AND (title LIKE '%${search}%' OR description LIKE '%${search}%')`;
    }
    query += ` ORDER BY created_at DESC`;
    
    db.all(query, (err, tasks) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(tasks);
    });
});

// VULNERABILITY 9: XSS through unescaped task content
app.post('/api/tasks', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const { title, description } = req.body;
    const userId = req.session.userId;
    
    // VULNERABILITY 10: Using eval() unnecessarily
    try {
        // Dangerous use of eval - never do this!
        const sanitizedTitle = eval(`"${title.replace(/"/g, '\\"')}"`);
        
        const query = `INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)`;
        db.run(query, [userId, sanitizedTitle, description], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to create task' });
            }
            
            res.json({ 
                id: this.lastID, 
                message: 'Task created successfully',
                title: sanitizedTitle 
            });
        });
    } catch (error) {
        res.status(400).json({ error: 'Invalid task data' });
    }
});

// Update task
app.put('/api/tasks/:id', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const taskId = req.params.id;
    const { title, description, completed } = req.body;
    const userId = req.session.userId;
    
    // VULNERABILITY 11: No proper authorization check
    const query = `UPDATE tasks SET title = ?, description = ?, completed = ? WHERE id = ?`;
    
    db.run(query, [title, description, completed, taskId], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to update task' });
        }
        res.json({ message: 'Task updated successfully' });
    });
});

// Delete task
app.delete('/api/tasks/:id', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const taskId = req.params.id;
    
    // VULNERABILITY 12: SQL injection in delete
    const query = `DELETE FROM tasks WHERE id = ${taskId}`;
    
    db.run(query, (err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to delete task' });
        }
        res.json({ message: 'Task deleted successfully' });
    });
});

// Logout
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to logout' });
        }
        res.json({ message: 'Logged out successfully' });
    });
});

// VULNERABILITY 13: Debug endpoint that exposes sensitive info
app.get('/debug', (req, res) => {
    res.json({
        session: req.session,
        environment: process.env,
        secret: SECRET_KEY
    });
});

module.exports = {app,db}; // <- Export the app without listening

// ===========================================