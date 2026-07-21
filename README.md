# 🛡️ PhishTrap AI

**An Autonomous Deception-Driven Containment Cell & Active Threat Sinkhole Middleware**

PhishTrap AI is an interactive Streamlit application that demonstrates how a web application can detect malicious login attempts in real time — and instead of just blocking them, respond by feeding the attacker a stream of realistic-looking **fake data**, while quietly tracking the attempt behind the scenes.

It's built around a well-known blue-team concept called **deception technology (honeypotting)**: rather than only saying "access denied," you let the attacker *think* they succeeded, waste their time and resources, and leave behind a traceable fingerprint of what they did.

This project was built as a hands-on way to learn and demonstrate core concepts in **application security, secure Python architecture, and defensive engineering** — signature-based detection, structured data validation, safe error handling, and memory-efficient data streaming.

---

## 🎯 What It Actually Does

1. You submit a login attempt (or pick a ready-made attack payload from the dropdown).
2. The app inspects the input against a set of known attack patterns — SQL injection, XSS, brute-force/dictionary credentials, and automated bot signatures.
3. **If the input looks malicious:**
   - The session is instantly flagged and sandboxed.
   - Instead of a real backend response, the app streams back a table of **completely fake customer records** — generated on the fly, never touching or resembling real data.
   - One of those fake records is a hidden **canary token**: a decoy that looks like a real API key or credential. If that exact value ever turns up being reused elsewhere, it's proof the "leaked" data was actually taken and used.
4. **If the input looks legitimate**, it's simply logged as a benign event — no deception triggered.
5. Every event (malicious or not) is recorded in a live **Security Operations Center (SOC) dashboard**, showing threat level, attacker device/browser fingerprint, and a full historical log.
6. At any point, you can generate a **downloadable incident report** formatted after the NIST SP 800-61 incident-handling structure.

---

## 🖥️ Interface Overview

| Panel | What it shows |
|---|---|
| **Attacker Gateway Portal** (left) | A mock login form. Includes a "1-Click Exploit Payload" dropdown to instantly fire a pre-built SQLi, XSS, brute-force, or clean login attempt. |
| **SOC Console** (right) | Live threat-level indicator (Green / Orange / Red), event metrics, parsed attacker telemetry (browser, OS, device type, automation flag), full event history table, and the compliance report generator. |

---

## ⚙️ How It's Built — Architecture

The project is split into six focused modules, each with a single clear responsibility:

```
phishtrap_ai/
├── config.py       # Central registry of all detection rules & constants
├── exceptions.py   # Custom error types + safe error handling
├── models.py       # Strict data schemas (Pydantic v2)
├── middleware.py   # The actual detection engine
├── generator.py    # Fake data generator + canary token logic
├── app.py          # Streamlit UI tying everything together
└── requirements.txt
```

### `config.py` — Detection Rules Registry
A single, thread-safe configuration object holding every pre-compiled detection pattern:
- **SQL Injection**: tautologies (`OR 1=1`), `UNION SELECT` structures, comment-based obfuscation (`/**/`), hex-encoded payloads, time-based blind SQLi (`SLEEP()`, `WAITFOR DELAY`), and more.
- **XSS**: malicious event handlers (`onerror=`, `onload=`), `<script>`/`<iframe>`/`<svg>` injection vectors, `javascript:` URIs, and encoded payload variants.
- **Brute Force**: dictionary usernames/passwords and known breached credential pairs.
- **Automated Agent Detection**: flags known scanning tools and scripted clients (`sqlmap`, `curl`, `python-requests`, headless browsers, etc.) by User-Agent.

All regex patterns are compiled once at startup, not on every request — kept in one place so the rules are easy to audit and extend.

### `exceptions.py` — Safe Failure Handling
A custom exception hierarchy (`SignatureCompromiseError`, `DataSynthesisFailure`, `IsolationSandboxBreach`, `TelemetryExtractionException`) ensures that **no internal error, file path, or stack trace ever reaches the user interface**. A decorator wraps risky functions and converts any unexpected failure into a safe, generic message — while the real detail is still logged internally for debugging.

### `models.py` — Strict Data Contracts
Every piece of data that moves through the system is validated using **Pydantic v2**:
- `AttackerFingerprint` — browser, OS, device type, automation flag, and a calculated risk score (0–100).
- `IncidentLogEntry` — timestamped audit record with source IP, threat classification, and mapped MITRE ATT&CK technique IDs (e.g. `T1190`, `T1110`).
- `SyntheticCustomerRecord` — the fake data shape used for the deception response, including the `is_canary` flag.

### `middleware.py` — The Detection Engine
The `SecurityInspectionEngine` is the heart of the system:
- Normalizes incoming input first (URL-decoding, HTML-unescaping, stripping comment-based obfuscation) so attackers can't sneak payloads past the filters using encoding tricks.
- Checks the cleaned input against every rule group from `config.py`.
- Builds a structured fingerprint from the User-Agent string.
- Calculates a weighted risk score and threat classification.
- Returns a clear, typed verdict — deterministic and side-effect-free, so the same input always produces the same result.

### `generator.py` — The Deception Engine
The `DeceptionDataFactory` streams fake customer records using a Python **generator** (`yield`) instead of building a big list in memory — keeping memory usage flat (O(1)) no matter how many fake rows are requested. Two deception techniques are layered in:
- A small artificial delay per record, designed to waste an automated scraper's time.
- A **canary token** — one record per stream, placed at a random position, disguised as a live API key or account credential, but secretly traceable.

### `app.py` — The Console
Brings everything together into the two-panel Streamlit interface described above, with session-state sandboxing: once a session is flagged as compromised, it's permanently locked out of any "genuine" code path for the rest of that session — it can only ever see fake data from that point on.

---

## 🧠 Concepts Demonstrated

- Signature-based intrusion detection (regex pattern matching against OWASP-style attack payloads)
- Deception technology / honeypotting
- Canary tokens for breach detection
- Basic attacker fingerprinting from HTTP headers
- MITRE ATT&CK technique mapping
- Memory-efficient data generation using Python generators
- Strict data validation with Pydantic v2
- Clean exception handling that avoids leaking internal details
- Thread-safe Singleton design pattern

---

## 🚀 Getting Started

```bash
git clone <this-repo-url>
cd phishtrap_ai
pip install -r requirements.txt
streamlit run app.py
```

Then open the local URL Streamlit gives you, pick a scenario from the dropdown on the left, and watch the SOC console react on the right.

---

## 🛠️ Tech Stack

- **Python 3.10+**
- **Streamlit** — interactive UI
- **Pydantic v2** — data validation and typed models
- **Faker** — synthetic data generation

No other third-party dependencies.

---

## ⚠️ Honest Scope & Disclaimer

This is a **learning project and working prototype**, not a production security product. It's meant to demonstrate the *concept* of deception-based defense in a self-contained, easy-to-read codebase — it doesn't integrate with a real backend, real user database, or real network traffic. All "leaked" data is synthetic and generated locally by Faker; nothing here ever touches real customer information.

If you're studying application security, WAF design, or honeypot techniques, this repo is meant to give you something concrete and readable to learn from and extend.

---

## 📄 License

Feel free to fork, modify, and use this project for learning purposes.
