# PhishTrap AI
### Autonomous Deception-Driven Containment Cell & Active Threat Sinkhole Middleware

A self-contained Streamlit application demonstrating an in-app WAF /
honeypot pattern: deterministic signature-based inspection, attacker
fingerprinting, and generator-driven synthetic-data deception with an
embedded canary token.

## Run it

```bash
pip install -r requirements.txt
streamlit run app.py
```

## File map

| File | Responsibility |
|---|---|
| `config.py` | Thread-safe Singleton holding every compiled regex signature (SQLi, XSS, brute force, automated-agent heuristics) and system constants (`THROTTLE_DELAY_DEFAULT`, `RATE_LIMIT_CAP`, `CANARY_MARKER`). |
| `exceptions.py` | `PhishTrapException` hierarchy + `mask_internal_errors` decorator so no stack trace/schema ever reaches the UI. |
| `models.py` | Pydantic v2 contracts: `AttackerFingerprint`, `IncidentLogEntry`, `SyntheticCustomerRecord`. |
| `middleware.py` | `SecurityInspectionEngine` — normalizes input, matches signatures, builds fingerprints, produces a typed verdict + audit log entry. Never raises for "normal" malicious input. |
| `generator.py` | `DeceptionDataFactory` — O(1)-memory generator streaming Faker-based fake customer records, with one row per stream disguised as a canary API key/credential containing `CANARY_MARKER`. |
| `app.py` | Two-column Streamlit console: attacker-facing fake login (left) + SOC console with threat-light, metrics, telemetry, event history, and a downloadable NIST SP 800-61-style Markdown report (right). |

## How the demo flow works

1. Pick a scenario from the **1-Click Exploit Payload** dropdown (or type your own credentials) and submit.
2. `SecurityInspectionEngine.inspect()` normalizes the input (URL/HTML decode, comment-block stripping) and checks it against the compiled signature groups.
3. If malicious: the session is latched into `is_compromised = True` (one-way — it cannot un-flip for the rest of that session) and routed to `DeceptionDataFactory`, which streams back 25 synthetic customer rows, one of which secretly carries the canary marker.
4. Every event — malicious or benign — becomes a typed `IncidentLogEntry` shown in the SOC console's event table.
5. Once at least one event exists, you can download a compiled Markdown incident report modeled on NIST SP 800-61 section structure (Executive Summary → Detection & Analysis → Containment → Telemetry → Recommendations).
6. Use **Reset Demo Session** in the sidebar to clear all session state and start over.

## Notes on scope

- All "customer data" leaked back to an attacker is 100% synthetic (Faker-generated) — nothing here touches or resembles real user data.
- The exploit payloads are inert strings evaluated only against this app's own regex-based detector; nothing here executes SQL or renders untrusted HTML/JS.
- No external network calls or third-party services beyond `streamlit`, `pydantic`, and `faker`.
