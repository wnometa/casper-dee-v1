# CASPER DEE v1.0

### Cybersecurity Assessment, Surveillance, Protection & Exposure Response — Digital Enterprise Edition

**By Wiltecon Technologies**  
**Founder & Creator: Wilson Nometa**

CASPER DEE is an open-source cybersecurity assessment and exposure-management platform designed to help organizations identify security weaknesses, understand their exposure, and improve their security posture.

Version 1.0 provides a foundation for security assessment, vulnerability findings, authorized target scanning, threat analysis, attack-path visualization, audit logging, and an AI-powered security assistant.

---

## 🚀 Features

### 🔐 Authentication & Organizations
- User registration and login
- Organization/workspace management
- Role-based access control
- Owner, Admin, Analyst, and Viewer roles
- Row Level Security (RLS)

### 🎯 Authorized Target Management
CASPER DEE allows organizations to register authorized security assessment targets.

Supported target types:

- URL
- Host
- CIDR range
- IP range

Targets can be marked as:

- Pending
- Authorized
- Revoked

Only authorized targets should be assessed.

### 🔎 Security Scanning

CASPER DEE V1 includes a non-destructive web security scanner that analyzes authorized URLs for issues including:

- Missing HSTS
- Missing Content-Security-Policy
- Missing X-Frame-Options
- Missing X-Content-Type-Options
- Missing Referrer-Policy
- Missing Permissions-Policy
- Server version disclosure
- X-Powered-By disclosure
- Inline scripts
- Inline event handlers
- Mixed-content resources
- Insecure HTTP form submissions
- HTTPS → HTTP redirects
- Connection and accessibility issues

Scan results include:

- Severity
- CVSS score
- Evidence
- Recommended remediation
- External exposure status

### 🤖 CASPER AI

CASPER AI is the AI-powered security assistant built into CASPER DEE.

It is designed to help users:

- Understand security findings
- Explain cybersecurity concepts
- Interpret scan results
- Recommend remediation steps
- Analyze security questions
- Assist security analysts

CASPER AI runs through a Supabase Edge Function and connects to an external AI provider.

**Important:** CASPER AI requires an API key from an AI provider.

When deploying your own copy of CASPER DEE, you must provide **your own AI API key**.

Never commit an AI API key to GitHub or place it directly in frontend source code.

AI provider credentials should be stored as secure server-side/Supabase Edge Function secrets.

### 🛡️ Threat & Risk Management
- Threat scenarios
- Risk scores
- Attack paths
- Security findings
- Finding status tracking
- Remediation information

### 📋 Audit Logging

CASPER DEE records important security-related actions, including scan activity, to provide an audit trail for organizations.

---

# 🏗️ Technology Stack

CASPER DEE V1 uses:

- React
- TypeScript
- Vite
- Supabase
- PostgreSQL
- Supabase Authentication
- Supabase Row Level Security
- Supabase Edge Functions
- Deno
- Lucide Icons

---

# ☁️ Supabase

Supabase provides the backend infrastructure for CASPER DEE.

It is used for:

- Authentication
- PostgreSQL database
- Organizations
- Users and roles
- Assets
- Scan targets
- Scan jobs
- Findings
- Threat scenarios
- Attack paths
- Audit logs
- Edge Functions

The repository contains the database migrations required to recreate the CASPER DEE database structure.

Each deployment should use its **own Supabase project**.

Do not use the original developer's Supabase project unless you have explicit permission to do so.

---

# 🤖 CASPER AI Configuration

CASPER AI requires an external AI provider.

The AI API key must be configured as a Supabase Edge Function secret.

Example:

```bash
supabase secrets set AI_API_KEY="YOUR_API_KEY"
