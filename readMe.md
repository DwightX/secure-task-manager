# Vulnerable Task Manager – DevSecOps Demo

A purposly insecure Node.js application built to demonstrate security testing, secure coding practices, and CI/CD security automation.

---

## 📌 Overview

This project simulates a task management application containing **intentional vulnerabilities** to show:

* Integration of security tools (SAST & DAST)
* Identification and remediation of vulnerabilities
* Automated security testing in CI/CD pipelines

---

## 🛠️ Technology Stack

| Layer    | Tools & Frameworks                      |
| -------- | --------------------------------------- |
| Backend  | Node.js, Express, SQLite                |
| Frontend | HTML, CSS, JavaScript                   |
| Security | Semgrep (SAST), Trivy, OWASP ZAP (DAST) |

---

## 🔒 Security Automation

### CI/CD Workflows (GitHub Actions)

| Workflow             | Purpose                                    | Tools Used                        |
| -------------------- | ------------------------------------------ | --------------------------------- |
| `semgrep.yml`        | Static code analysis (SAST)                | Semgrep                           |
| `security-tests.yml` | Dynamic and dependency scanning; API tests | Trivy, OWASP ZAP, Jest, Supertest |

### Automated Checks

* Static Application Security Testing (SAST) with Semgrep
* Vulnerability scanning of dependencies with Trivy
* Dynamic Application Security Testing (DAST) with OWASP ZAP
* Automated API testing using Jest & Supertest
