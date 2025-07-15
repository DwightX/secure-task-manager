# Vulnerable Task Manager – DevSecOps Project

A deliberately insecure Node.js application developed to demonstrate security testing, secure coding practices, and CI/CD security automation.

## Project Overview

This task management application includes intentional vulnerabilities to showcase:
- Security scanning integration (SAST/DAST)
- Vulnerability identification and remediation
- CI/CD security automation

### Technology Stack
- **Backend**: Node.js, Express, SQLite
- **Frontend**: Vanilla HTML, CSS, JavaScript
- **Security Tools**: Semgrep (SAST), Trivy, OWASP ZAP (DAST)

## Security Automation

### GitHub Actions Workflows

| Workflow           | Purpose                          | Tools Used          |
|--------------------|----------------------------------|---------------------|
| `semgrep.yml`      | Static code analysis             | Semgrep             |
| `security-tests.yml` | Dynamic scanning and testing    | Trivy, OWASP ZAP, Jest |

### Automated Security Checks
- Static Application Security Testing (SAST) with Semgrep
- Dependency vulnerability scanning with Trivy
- Dynamic Application Security Testing (DAST) with OWASP ZAP
- Automated API testing with Jest and Supertest

## Key Vulnerabilities (Intentional)
- SQL Injection in login and search endpoints
- Cross-Site Scripting (XSS) vulnerabilities
- Hardcoded credentials and secrets
- Insecure session configuration
- Missing input validation and sanitization
- Vulnerable dependencies

## Installation

```bash
git clone https://github.com/yourusername/vulnerable-task-manager.git
cd vulnerable-task-manager
npm install
npm start

The application will be available at http://localhost:3000

Testing
To run the test suite:

bash
npm test
Security scans are automatically executed via GitHub Actions on:

Push to main branch

Pull requests

Scheduled basis

What This Project Demonstrates
Integration of security tools in CI/CD pipelines

Identification and remediation of common web vulnerabilities

Automated security testing workflows

Secure coding practices in Node.js applications
