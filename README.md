# 🛡️ BANKISM
### Blue-Team Firewall & Guardrail Defense

**A security-focused prototype for detecting suspicious banking requests before they proceed to further validation.**

<p align="center">
  <img src="https://img.shields.io/badge/Project-Cybersecurity-0D9488?style=for-the-badge" alt="Cybersecurity project">
  <img src="https://img.shields.io/badge/Runtime-Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js">
  <img src="https://img.shields.io/badge/Backend-Express.js-111827?style=for-the-badge&logo=express" alt="Express.js">
  <img src="https://img.shields.io/badge/Status-Prototype-F59E0B?style=for-the-badge" alt="Prototype">
</p>

---

## 🚨 The Problem

Banking workflows need to treat incoming instructions carefully. Suspicious requests, invalid transaction details, and attempts to override security rules should not simply be trusted.

## 💡 Our Solution

**Bankism** is a simulated banking security dashboard that checks requests against basic security rules and returns a structured verdict.

It combines a simple web interface with a Node.js and Express backend to demonstrate a blue-team security workflow.

## ✨ Key Features

- 🔍 **Suspicious Phrase Detection** — checks for a defined set of instruction-override phrases.
- 🔐 **Request Validation** — checks request text, transaction amount, and recipient.
- ⚡ **Instant Verdicts** — returns structured JSON results through an API.
- 🖥️ **Interactive Dashboard** — displays the verdict and its explanation.
- 🧱 **Malformed JSON Handling** — returns a controlled security response for invalid JSON bodies.

## ⚖️ Security Decision System

| Verdict | Meaning |
|---|---|
| 🛑 `BLOCK` | A configured security or validation rule detected an issue. |
| 🔎 `REVIEW` | Basic checks passed; further validation is still required. |

> **Important:** `REVIEW` does not mean a transaction is approved. Bankism does not execute transfers or connect to real banking systems.

## 🧰 Tech Stack

| Technology | Purpose |
|---|---|
| HTML | Dashboard structure |
| JavaScript | Browser-side interactions |
| Node.js | Server runtime |
| Express.js | API and static-file serving |

## 🏗️ How It Works

1. **Submit:** A user enters a simulated banking request.
2. **Inspect:** The backend checks the request text and transaction fields.
3. **Decide:** The rule-based detector returns `BLOCK` or `REVIEW`.
4. **Display:** The dashboard shows the verdict and rationale.

```text
User Request
     │
     ▼
Bankism Dashboard
     │
     ▼
Express API (/api/check)
     │
     ▼
Rule-Based Security Checks
     │
     ├── Suspicious / Invalid ──► BLOCK
     │
     └── Basic Checks Pass ─────► REVIEW
                                      │
                                      ▼
                              Further Validation
```

## 🚀 Run Locally

**Prerequisites:** Node.js and npm installed.

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd BANKISM
npm install
node server.js
```

Open **http://localhost:3000** in your browser.

Replace `YOUR_GITHUB_REPOSITORY_URL` with your actual repository URL after publishing the project.

## 🧪 Test Scenarios

| Scenario | Expected Result |
|---|---|
| Suspicious override phrase | `BLOCK` |
| Empty request | `BLOCK` |
| Zero or negative amount | `BLOCK` |
| Missing recipient | `BLOCK` |
| Ordinary request passing basic checks | `REVIEW` |
| Malformed JSON body | `BLOCK` with `INVALID_JSON` |

These are prototype test scenarios, not proof of complete attack detection.

## ⚠️ Limitations & Responsible Use

- Detection currently relies on rule-based phrase matching.
- New or disguised attacks may go undetected.
- Legitimate requests may trigger false positives.
- Authentication, authorization, and production-grade banking controls are not implemented.
- No real transactions are processed.

**Bankism is an educational cybersecurity prototype, not a production banking firewall or a guarantee of security.**

## 🔭 Future Scope

- Expand adversarial test coverage.
- Evaluate false positives and false negatives.
- Improve detection using additional analysis techniques.
- Add secure authentication, audit logging, and monitoring.
- Explore AI-assisted detection with measurable evaluation.

---

### Built for a cybersecurity hackathon 🛡️

*Demonstrating how a defensive validation layer can inspect simulated banking requests before further review.*
