// app.js - Main server file (INTENTIONALLY VULNERABLE FOR LEARNING)
require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const _ = require('lodash');

const app = express();
const PORT = process.env.PORT || 3000;

// VULNERABILITY 1: Secrets Management
// LEARNING OBJECTIVE: Understand proper secrets management and key rotation
// CURRENT ISSUE: While this reads from environment variables (improvement from hardcoding),
// the real vulnerability is in the deployment and lifecycle management of secrets.
// SECURITY IMPACT: If .env file is committed to version control, exposed in logs,
// or accessed by unauthorized users, the secret is compromised.
// ATTACK SCENARIOS: 
// - Secrets exposed in GitHub repos, Docker images, or CI/CD logs
// - Unauthorized access to production servers reveals .env files
// - Secrets never rotated, so one-time compromise has lasting impact
// LEARNING QUESTIONS:
// - How do you implement automated secret rotation?
// - What's the difference between secrets at rest vs. in transit?
// - How would you detect if a secret has been compromised?
// - What are the security implications of using the same secret across environments?
// DESIRED OUTCOME: Implement proper secrets management with rotation capabilities
const MY_SECRET_KEY = process.env.MY_SECRET_KEY

if (!MY_SECRET_KEY) {
    console.error('❌ MY_SECRET_KEY is not set! Exiting...');
    process.exit(1);
}

// VULNERABILITY 2: Vulnerable Dependencies (Supply Chain Security)
// LEARNING OBJECTIVE: Understand dependency management and supply chain security
// CURRENT ISSUE: Using lodash 4.17.10 which contains known security vulnerabilities
// SECURITY IMPACT: Vulnerable dependencies can be exploited to:
// - Execute arbitrary code on the server
// - Access sensitive data or file systems
// - Perform denial of service attacks
// ATTACK SCENARIOS:
// - Prototype pollution attacks through lodash vulnerabilities
// - Malicious packages uploaded to npm with similar names (typosquatting)
// - Compromised legitimate packages pushing malicious updates
// LEARNING QUESTIONS:
// - How do you establish a secure dependency update process?
// - What's the difference between direct and transitive dependencies?
// - How can you monitor for new vulnerabilities in your dependencies?
// - What are Software Bill of Materials (SBOM) and why are they important?
// TOOLS TO RESEARCH: npm audit, Snyk, OWASP Dependency-Check, Dependabot
// DESIRED OUTCOME: Implement automated dependency scanning and update processes

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

// VULNERABILITY 3: Insecure Session Configuration
// LEARNING OBJECTIVE: Understand session security and cookie attributes
// CURRENT ISSUE: Multiple session security misconfigurations that expose users to attacks
// SECURITY IMPACT: 
// - Session hijacking through network interception
// - Cross-site scripting (XSS) attacks can steal session cookies
// - Cross-site request forgery (CSRF) attacks can perform actions on behalf of users
// ATTACK SCENARIOS:
// - Attacker on same network captures session cookies over HTTP
// - Malicious JavaScript reads session cookie and sends to attacker's server
// - Attacker tricks user into clicking malicious link that performs actions
// LEARNING QUESTIONS:
// - What's the difference between session hijacking and session fixation?
// - How do different cookie attributes (secure, httpOnly, sameSite) protect against specific attacks?
// - What are the trade-offs between security and usability for session expiration?
// - How would you implement secure session management in a microservices architecture?
// DESIRED OUTCOME: Configure sessions with appropriate security attributes for production
app.use(session({
    secret: MY_SECRET_KEY,
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false, // VULNERABILITY: Should be true in production with HTTPS
        httpOnly: true,
        sameSite: 'lax', // Added to mitigate CSRF attacks
        maxAge: 24 * 60 * 60 * 1000  // 24 hours
    }
}));

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', (req, res) => {  
    db.get('SELECT 1', (err, row) => {
        if (err) {
            return res.status(500).send(err.message);
        }
        if (!row) {
            return res.status(500).send('Database not reachable');
        }
        res.status(200).send('OK');
    });
});

// VULNERABILITY 4: SQL Injection in Authentication
// LEARNING OBJECTIVE: Understand SQL injection attacks and their prevention
// CURRENT ISSUE: User input directly concatenated into SQL query without sanitization
// SECURITY IMPACT: Complete compromise of database and application security
// ATTACK SCENARIOS:
// - Authentication bypass: Input "admin' OR '1'='1' --" logs in as any user
// - Data extraction: Input "' UNION SELECT username, password, email FROM users --"
// - Data destruction: Input "'; DROP TABLE users; --" destroys user data
// - Privilege escalation: Access admin accounts or sensitive data
// LEARNING QUESTIONS:
// - What's the difference between parameterized queries and stored procedures?
// - How do different SQL injection types (UNION, Boolean, Time-based) work?
// - What are the limitations of input validation as a defense mechanism?
// - How would you implement database-level security controls?
// DESIRED OUTCOME: Implement parameterized queries and proper input validation
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        async function verifyPassword(plainPassword, hashedPassword) {
            try {
                const match = await bcrypt.compare(plainPassword, hashedPassword);
                return match; // true if they match, false otherwise
            } catch (error) {
                console.error("Error verifying password:", error);
                return false;
            }
        }
        try {
            const isMatch = await verifyPassword(password, user.password);
            if (isMatch) {
                req.session.userId = user.id;
                req.session.username = user.username;
                return res.json({ success: true });
            } else {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
        } catch (error) {
            console.error('Error during password verification:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    });
});


// VULNERABILITY 6: Insufficient Input Validation
// LEARNING OBJECTIVE: Understand comprehensive input validation and sanitization
// CURRENT ISSUE: No validation on user registration data
// SECURITY IMPACT: Data integrity issues, potential for abuse, and security bypasses
// ATTACK SCENARIOS:
// - Extremely long inputs cause denial of service
// - Special characters break application logic
// - Empty or null inputs cause application errors
// - Malicious usernames containing SQL or JavaScript
// LEARNING QUESTIONS:
// - What's the difference between whitelist and blacklist validation?
// - How do you implement proper email validation?
// - What are the security implications of different character encodings?
// - How would you implement rate limiting to prevent abuse?
// DESIRED OUTCOME: Implement comprehensive input validation and sanitization
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    
    // VULNERABILITY 7: Plain Text Password Storage
    // LEARNING OBJECTIVE: Understand secure password storage practices
    // CURRENT ISSUE: Passwords stored in database without any protection
    // SECURITY IMPACT: Immediate credential compromise upon database access
    // ATTACK SCENARIOS:
    // - Database backups contain plain text passwords
    // - Log files may accidentally contain password data
    // - Database administrators can see all user passwords
    // - Compliance violations with data protection regulations
    // LEARNING QUESTIONS:
    // - What are the different types of password hashing algorithms?
    // - How do you implement password complexity requirements?
    // - What's the purpose of password salting and how do you implement it?
    // - How would you migrate from plain text to hashed passwords?
    // DESIRED OUTCOME: Hash passwords before storing them in the database

    const saltRouds = 10;

    bcrypt.genSalt(saltRouds, (err, salt) => {
        bcrypt.hash(password, salt, (err, hash) => {

            const query = `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`;
    
            db.run(query, [username, email, hash], function(err) {
                if (err) {
                    return res.status(400).json({ error: 'Username already exists' });
                }
                res.json({ message: 'Registration successful' });
            });

        });
    })
});

app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// VULNERABILITY 8: SQL Injection in Data Retrieval
// LEARNING OBJECTIVE: Understand SQL injection in SELECT statements and data exfiltration
// CURRENT ISSUE: Search parameter directly concatenated into SQL query
// SECURITY IMPACT: Unauthorized data access and potential data theft
// ATTACK SCENARIOS:
// - Data exfiltration: "' UNION SELECT username, password, email, null, null, null FROM users --"
// - Information disclosure: Extract sensitive data from other tables
// - Database fingerprinting: Determine database structure and sensitive locations
// - Privilege escalation: Access data belonging to other users
// LEARNING QUESTIONS:
// - How do UNION-based SQL injection attacks work?
// - What information can attackers gather through error-based SQL injection?
// - How would you implement secure search functionality?
// - What are the differences between SQL injection in different database systems?
// DESIRED OUTCOME: Implement secure search with parameterized queries

app.get('/api/tasks', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    console.log(req.session);
    const userId = req.session.userId;
    const search = req.query.search || '';
    
    // DANGEROUS: SQL injection vulnerability through search parameter
    let query = `SELECT * FROM tasks WHERE user_id = ?`;
    let params = [userId];

    if (search) {
        query += ` AND (title LIKE ? OR description LIKE ?)`;
        params.push(`%${search}%`, `%${search}%`);
        // Solution: Use parameterized queries to prevent SQL injection
    }
    query += ` ORDER BY created_at DESC`;
    db.all(query,params, (err, tasks) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(tasks);
    });
});

// VULNERABILITY 9: Stored Cross-Site Scripting (XSS)
// LEARNING OBJECTIVE: Understand XSS attacks and output encoding
// CURRENT ISSUE: User input stored and displayed without proper sanitization
// SECURITY IMPACT: JavaScript execution in other users' browsers
// ATTACK SCENARIOS:
// - Session hijacking: Steal session cookies and impersonate users
// - Credential theft: Create fake login forms to capture passwords
// - Malware distribution: Redirect users to malicious websites
// - Defacement: Modify page content to spread misinformation
// LEARNING QUESTIONS:
// - What's the difference between stored, reflected, and DOM-based XSS?
// - How do Content Security Policy (CSP) headers help prevent XSS?
// - What are the different approaches to output encoding/escaping?
// - How would you implement a secure content management system?
// DESIRED OUTCOME: Implement proper output encoding and input sanitization
app.post('/api/tasks', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const { title, description } = req.body;
    const userId = req.session.userId;
    
    // VULNERABILITY 10: Code Injection through eval()
    // LEARNING OBJECTIVE: Understand code injection attacks and safe alternatives
    // CURRENT ISSUE: Using eval() with user input enables arbitrary code execution
    // SECURITY IMPACT: Complete server compromise and remote code execution
    // ATTACK SCENARIOS:
    // - File system access: "'; require('fs').readFileSync('/etc/passwd', 'utf8'); '"
    // - Network requests: Execute code to exfiltrate data to external servers
    // - System commands: Execute shell commands on the server
    // - Denial of service: Crash the application with malicious code
    // LEARNING QUESTIONS:
    // - What are the security implications of dynamic code execution?
    // - How do you safely parse and validate JSON data?
    // - What are template injection attacks and how do they relate to code injection?
    // - How would you implement secure dynamic content generation?
    // DESIRED OUTCOME: Remove eval() and implement safe string processing
    try {
        // DANGEROUS: eval() with user input - enables arbitrary code execution
        // const sanitizedTitle = title;
        
        const query = `INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)`;
        db.run(query, [userId, title, description], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to create task' });
            }
            
            res.json({ 
                id: this.lastID, 
                message: 'Task created successfully',
                title: title 
            });
        });
    } catch (error) {
        res.status(400).json({ error: 'Invalid task data' });
    }
});

// VULNERABILITY 11: Insecure Direct Object Reference (IDOR)
// LEARNING OBJECTIVE: Understand access control and authorization mechanisms
// CURRENT ISSUE: No verification that the task belongs to the current user
// SECURITY IMPACT: Unauthorized access to other users' data
// ATTACK SCENARIOS:
// - Horizontal privilege escalation: Access other users' tasks
// - Data modification: Edit or delete other users' content
// - Information disclosure: Enumerate and access sensitive data
// - Business logic bypass: Circumvent application restrictions
// LEARNING QUESTIONS:
// - What's the difference between authentication and authorization?
// - How do you implement proper access control mechanisms?
// - What are the different types of access control models?
// - How would you design secure APIs with proper authorization?
// DESIRED OUTCOME: Implement proper authorization checks for all data access
app.put('/api/tasks/:id', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const taskId = req.params.id;
    const { title, description, completed } = req.body;
    const userId = req.session.userId;
    
    // DANGEROUS: No authorization check - any user can modify any task
    const query = `UPDATE tasks SET title = ?, description = ?, completed = ? WHERE id = ?`;
    
    db.run(query, [title, description, completed, taskId], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to update task' });
        }
        res.json({ message: 'Task updated successfully' });
    });
});

// VULNERABILITY 12: SQL Injection in DELETE Operations
// LEARNING OBJECTIVE: Understand SQL injection in data manipulation operations
// CURRENT ISSUE: Task ID directly concatenated into DELETE query
// SECURITY IMPACT: Unauthorized data deletion and potential data loss
// ATTACK SCENARIOS:
// - Mass data deletion: "1; DELETE FROM users; --" destroys all user data
// - Selective data deletion: Remove specific records to cover tracks
// - Database structure manipulation: Drop tables or modify schema
// - Combined with IDOR: Any user can delete any data
// LEARNING QUESTIONS:
// - How do SQL injection attacks differ between SELECT, INSERT, UPDATE, and DELETE?
// - What are the business impact considerations of data deletion attacks?
// - How would you implement secure data deletion with audit trails?
// - What are the considerations for data recovery after malicious deletion?
// DESIRED OUTCOME: Implement parameterized queries and proper authorization
app.delete('/api/tasks/:id', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const taskId = req.params.id;
    
    // DANGEROUS: SQL injection in DELETE operation
    const query = `DELETE FROM tasks WHERE id = ${taskId}`;
    
    db.run(query, (err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to delete task' });
        }
        res.json({ message: 'Task deleted successfully' });
    });
});

app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to logout' });
        }
        res.json({ message: 'Logged out successfully' });
    });
});

// VULNERABILITY 13: Information Disclosure through Debug Endpoints
// LEARNING OBJECTIVE: Understand information disclosure vulnerabilities
// CURRENT ISSUE: Debug endpoint exposes extremely sensitive system information
// SECURITY IMPACT: Complete system compromise through information disclosure
// ATTACK SCENARIOS:
// - Credential theft: Expose database credentials and API keys
// - Session hijacking: Access other users' session data
// - System reconnaissance: Gather information for further attacks
// - Privilege escalation: Use exposed secrets to access other systems
// LEARNING QUESTIONS:
// - What information should never be exposed in production?
// - How do you implement secure debugging and monitoring?
// - What are the risks of exposing environment variables?
// - How would you design secure error handling and logging?
// DESIRED OUTCOME: Remove debug endpoints and implement secure error handling
app.get('/debug', (req, res) => {
    // DANGEROUS: Exposes sensitive system information
    res.json({
        session: req.session,
        environment: process.env,
        secret: MY_SECRET_KEY
    });
});

// VULNERABILITY 14: Test Endpoints in Production
// LEARNING OBJECTIVE: Understand the risks of leaving test code in production
// CURRENT ISSUE: Test endpoints with known vulnerabilities accessible in production
// SECURITY IMPACT: Easy targets for attackers to exploit known vulnerabilities
// ATTACK SCENARIOS:
// - Automated scanning: Attackers scan for common test endpoints
// - Vulnerability testing: Use test endpoints to confirm exploitable vulnerabilities
// - Bypassing security controls: Test endpoints may have weaker security
// - Information gathering: Learn about application structure and technologies
// LEARNING QUESTIONS:
// - How do you separate test code from production code?
// - What are the risks of exposing application internals?
// - How would you implement secure testing practices?
// - What are the considerations for security testing in CI/CD pipelines?
// DESIRED OUTCOME: Remove test endpoints and implement proper environment separation

app.get('/test/search', (req, res) => {
    const search = req.query.q || '';
    // DANGEROUS: SQL injection vulnerability in test endpoint
    const query = `SELECT * FROM tasks WHERE title LIKE '%${search}%'`;
    db.all(query, (err, tasks) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(tasks);
    });
});

app.get('/test/xss', (req, res) => {
    const input = req.query.input || '';
    // DANGEROUS: XSS vulnerability in test endpoint
    res.send(`<h1>Hello ${input}</h1>`);
});

// ADDITIONAL SECURITY ISSUES TO ADDRESS:
// 
// VULNERABILITY 15: No Rate Limiting
// LEARNING OBJECTIVE: Understand denial of service and brute force attack prevention
// SECURITY IMPACT: Application abuse and resource exhaustion
// DESIRED OUTCOME: Implement rate limiting for all endpoints
//
// VULNERABILITY 16: Missing CSRF Protection
// LEARNING OBJECTIVE: Understand cross-site request forgery attacks
// SECURITY IMPACT: Unauthorized actions performed on behalf of users
// DESIRED OUTCOME: Implement CSRF token validation
//
// VULNERABILITY 17: No Input Length Limits
// LEARNING OBJECTIVE: Understand denial of service through resource exhaustion
// SECURITY IMPACT: Application crashes and resource exhaustion
// DESIRED OUTCOME: Implement input validation with length limits
//
// VULNERABILITY 18: Missing Content Security Policy
// LEARNING OBJECTIVE: Understand additional XSS protection mechanisms
// SECURITY IMPACT: Reduced XSS attack surface
// DESIRED OUTCOME: Implement comprehensive CSP headers
//
// VULNERABILITY 19: No HTTPS Enforcement
// LEARNING OBJECTIVE: Understand transport layer security
// SECURITY IMPACT: Man-in-the-middle attacks and data interception
// DESIRED OUTCOME: Implement HTTPS redirection and HSTS headers
//
// VULNERABILITY 20: Insecure Error Handling
// LEARNING OBJECTIVE: Understand information disclosure through error messages
// SECURITY IMPACT: System information leaked through error messages
// DESIRED OUTCOME: Implement secure error handling with proper logging
//
// VULNERABILITY 21: No Security Monitoring
// LEARNING OBJECTIVE: Understand security observability and incident response
// SECURITY IMPACT: Inability to detect and respond to attacks
// DESIRED OUTCOME: Implement comprehensive security logging and monitoring
//
// VULNERABILITY 22: Weak Password Policy
// LEARNING OBJECTIVE: Understand password security requirements
// SECURITY IMPACT: Weak passwords enable brute force attacks
// DESIRED OUTCOME: Implement strong password requirements and validation
//
// VULNERABILITY 23: No Account Lockout
// LEARNING OBJECTIVE: Understand brute force attack prevention
// SECURITY IMPACT: Unlimited login attempts enable password guessing
// DESIRED OUTCOME: Implement account lockout after failed attempts
//
// VULNERABILITY 24: Missing Security Headers
// LEARNING OBJECTIVE: Understand HTTP security headers
// SECURITY IMPACT: Missing protection against various client-side attacks
// DESIRED OUTCOME: Implement comprehensive security headers

module.exports = { app, db };