"""
app.py
------
High-Fidelity Multi-View Security Console & Demo Matrix.

This is the Streamlit front end that ties every other module together
into a live, interactive demonstration:

  LEFT COLUMN  — Attacker Gateway Portal: a fake admin login form with
                 a "1-click exploit payload" selector for instant demo
                 firing (SQLi, brute force, or a clean legitimate login).

  RIGHT COLUMN — SOC Console: threat-level indicator, live metrics,
                 parsed telemetry, historical event table, and a
                 downloadable NIST SP 800-61-style incident report.

Session-state sandboxing: the moment a session is flagged as
compromised, it is switched onto the DeceptionDataFactory data path
and permanently blocked (for the rest of that session) from any
codepath that would represent "genuine" system access. Attempting to
bypass that boundary raises `IsolationSandboxBreach`, which is caught
at the UI boundary and rendered as a safe, generic message.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

import streamlit as st

from config import get_config
from exceptions import IsolationSandboxBreach, PhishTrapException
from generator import DeceptionDataFactory
from middleware import SecurityInspectionEngine
from models import IncidentLogEntry, ThreatClassification

# ----------------------------------------------------------------------
# Page configuration
# ----------------------------------------------------------------------
st.set_page_config(
    page_title="PhishTrap AI — Autonomous Deception Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

CONFIG = get_config()
ENGINE = SecurityInspectionEngine(CONFIG)
FACTORY = DeceptionDataFactory(CONFIG)

# ----------------------------------------------------------------------
# 1-click demo payloads
# ----------------------------------------------------------------------
_DEMO_PAYLOADS: dict[str, dict[str, str]] = {
    "— Select a scenario —": {"username": "", "password": ""},
    "🟢 Normal secure login": {"username": "j.harrison", "password": "Tr0ub4dor&9Zk!"},
    "🔴 SQLi — obfuscated tautology": {"username": "admin' OR 1=1/**/--", "password": "x"},
    "🔴 SQLi — UNION SELECT exfiltration": {
        "username": "wiley' UNION SELECT username,password FROM users--",
        "password": "irrelevant",
    },
    "🔴 XSS — event-handler injection": {
        "username": "<img src=x onerror=alert(document.cookie)>",
        "password": "n/a",
    },
    "🟠 Brute force — dictionary credentials": {"username": "admin", "password": "admin123"},
}

_FAKE_USER_AGENTS: dict[str, str] = {
    "🟢 Normal secure login": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "🔴 SQLi — obfuscated tautology": "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "🔴 SQLi — UNION SELECT exfiltration": "python-requests/2.31.0",
    "🔴 XSS — event-handler injection": "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/124.0.0.0",
    "🟠 Brute force — dictionary credentials": "Hydra v9.5",
    "— Select a scenario —": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
}

_DEMO_SOURCE_IPS: dict[str, str] = {
    "🟢 Normal secure login": "203.0.113.44",
    "🔴 SQLi — obfuscated tautology": "198.51.100.23",
    "🔴 SQLi — UNION SELECT exfiltration": "198.51.100.87",
    "🔴 XSS — event-handler injection": "192.0.2.15",
    "🟠 Brute force — dictionary credentials": "192.0.2.201",
    "— Select a scenario —": "203.0.113.10",
}


# ----------------------------------------------------------------------
# Session-state sandbox initialization
# ----------------------------------------------------------------------
def _init_session_state() -> None:
    defaults = {
        "is_compromised": False,
        "incident_log": [],  # List[IncidentLogEntry]
        "last_verdict_label": None,
        "last_fingerprint": None,
        "deception_records": [],
        "login_attempts": 0,
        "username_input": "",
        "password_input": "",
        "selected_scenario": "— Select a scenario —",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _mark_compromised() -> None:
    """
    One-way latch: once flipped, a session can never programmatically
    flip back to a trusted state within its own lifetime. This mirrors
    the requirement that a compromised session is permanently
    sandboxed away from genuine system parameters.
    """
    st.session_state["is_compromised"] = True


def _assert_sandboxed_access_allowed(*, requesting_genuine_resource: bool) -> None:
    """
    Guard clause called before any codepath that would touch a
    "genuine" (non-deceptive) system resource. If the session is
    compromised and genuine access is requested anyway, this is a
    programming-level containment failure and must hard-stop.
    """
    if st.session_state["is_compromised"] and requesting_genuine_resource:
        raise IsolationSandboxBreach(
            internal_detail="Compromised session attempted to reach a genuine resource path.",
            public_message="This session is isolated and cannot access that resource.",
        )


# ----------------------------------------------------------------------
# Rendering helpers
# ----------------------------------------------------------------------
def _threat_band_color(band: str) -> str:
    return {"GREEN": "#16a34a", "ORANGE": "#f59e0b", "RED": "#dc2626"}.get(band, "#6b7280")


def _render_threat_indicator(band: str) -> None:
    color = _threat_band_color(band)
    label = {"GREEN": "NOMINAL", "ORANGE": "ELEVATED", "RED": "ACTIVE CONTAINMENT"}.get(band, "UNKNOWN")
    st.markdown(
        f"""
        <div style="
            display:flex; align-items:center; gap:12px;
            padding:14px 18px; border-radius:10px;
            background:{color}1a; border:1.5px solid {color};
        ">
            <div style="width:16px; height:16px; border-radius:50%; background:{color};
                        box-shadow:0 0 10px {color};"></div>
            <div style="font-weight:700; letter-spacing:0.5px; color:{color}; font-size:15px;">
                THREAT LEVEL: {label}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _generate_nist_report(log_entries: List[IncidentLogEntry]) -> str:
    """Compile all Pydantic incident log entries into a markdown SP 800-61 style brief."""
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    lines: List[str] = [
        "# Incident Response Brief",
        "### NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide (aligned format)",
        "",
        f"**Report generated:** {generated_at}  ",
        f"**System:** PhishTrap AI — Autonomous Deception-Driven Containment Cell  ",
        f"**Total logged events:** {len(log_entries)}  ",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
    ]

    contained = [e for e in log_entries if e.was_contained]
    benign = [e for e in log_entries if not e.was_contained]
    lines.append(
        f"During the observed session window, **{len(contained)}** event(s) were classified as "
        f"malicious and contained via deception routing, while **{len(benign)}** event(s) were "
        f"evaluated as benign and permitted normal handling."
    )
    lines.append("")
    lines.append("## 2. Detection & Analysis")
    lines.append("")
    lines.append("| # | Timestamp (UTC) | Source IP | Classification | MITRE ATT&CK | Risk Score | Contained |")
    lines.append("|---|---|---|---|---|---|---|")
    for idx, entry in enumerate(log_entries, start=1):
        mitre_ids = ", ".join(t.value for t in entry.mitre_technique_ids) or "—"
        lines.append(
            f"| {idx} | {entry.iso_8601_timestamp} | {entry.source_ip} | "
            f"{entry.threat_classification.value} | {mitre_ids} | "
            f"{entry.fingerprint.risk_score} | {'✅ Yes' if entry.was_contained else '❌ No'} |"
        )
    lines.append("")

    lines.append("## 3. Containment, Eradication & Recovery")
    lines.append("")
    if contained:
        lines.append(
            "Containment was achieved automatically for each malicious event via deterministic "
            "signature interception (`SecurityInspectionEngine`) followed by routing into the "
            "`DeceptionDataFactory` sinkhole. No genuine backend resource was reachable at any point "
            "during a compromised session, consistent with the system's sandboxing guarantees."
        )
        lines.append("")
        lines.append("### Matched Signature Detail")
        for idx, entry in enumerate(contained, start=1):
            sigs = "; ".join(entry.matched_signatures) if entry.matched_signatures else "n/a"
            lines.append(f"- **Event {idx}** ({entry.threat_classification.value}): `{sigs}`")
    else:
        lines.append("No containment actions were necessary during this session window.")
    lines.append("")

    lines.append("## 4. Attacker Telemetry (Fingerprinting)")
    lines.append("")
    lines.append("| # | Browser Family | Device Profile | OS/Arch | Automated Agent | Threat Band |")
    lines.append("|---|---|---|---|---|---|")
    for idx, entry in enumerate(log_entries, start=1):
        fp = entry.fingerprint
        lines.append(
            f"| {idx} | {fp.browser_family.value} | {fp.device_profile.value} | "
            f"{fp.os_architecture} | {'Yes' if fp.is_automated_agent else 'No'} | {fp.threat_band} |"
        )
    lines.append("")

    lines.append("## 5. Post-Incident Recommendations")
    lines.append("")
    lines.append(
        "- Rotate any credentials that share a namespace with the dictionary values observed above.\n"
        "- Review upstream WAF/CDN rules for parity with the signature groups enforced in `config.py`.\n"
        "- Cross-reference the embedded canary marker (`" + CONFIG.CANARY_MARKER + "`) against "
        "outbound traffic logs and any public data-leak monitoring feeds to detect downstream reuse "
        "of sinkholed synthetic records.\n"
        "- No further action required if all events above show `Contained = Yes`."
    )
    lines.append("")
    lines.append("---")
    lines.append("*This report was generated automatically by PhishTrap AI and reflects only data "
                  "captured within this local demonstration session.*")

    return "\n".join(lines)


# ----------------------------------------------------------------------
# Core execution flow (fired by the 1-click payload or manual submit)
# ----------------------------------------------------------------------
def _execute_login_attempt(username: str, password: str, source_ip: str, user_agent: str) -> None:
    st.session_state["login_attempts"] += 1

    try:
        verdict, log_entry = ENGINE.inspect(
            username=username,
            password=password,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except PhishTrapException as exc:
        st.error(exc.to_safe_response())
        return

    st.session_state["incident_log"].append(log_entry)
    st.session_state["last_fingerprint"] = verdict.fingerprint

    if verdict.is_malicious:
        _mark_compromised()
        st.session_state["last_verdict_label"] = verdict.threat_classification.value
        try:
            _assert_sandboxed_access_allowed(requesting_genuine_resource=False)
            records = FACTORY.materialize(25, throttle_seconds=CONFIG.THROTTLE_DELAY_DEFAULT)
            st.session_state["deception_records"] = records
        except PhishTrapException as exc:
            st.error(exc.to_safe_response())
    else:
        st.session_state["last_verdict_label"] = "BENIGN"
        st.session_state["deception_records"] = []


# ----------------------------------------------------------------------
# UI — page header
# ----------------------------------------------------------------------
_init_session_state()

st.markdown(
    """
    <div style="display:flex; align-items:baseline; gap:14px; margin-bottom:4px;">
        <span style="font-size:32px; font-weight:800;">🛡️ PhishTrap AI</span>
        <span style="font-size:14px; color:#888;">Autonomous Deception-Driven Containment Cell & Active Threat Sinkhole</span>
    </div>
    """,
    unsafe_allow_html=True,
)
st.caption(
    "In-application interceptor middleware — deterministic signature inspection, "
    "attacker fingerprinting, and generator-driven deception, all sandboxed to this session."
)
st.divider()

left_col, right_col = st.columns([1, 1.3], gap="large")

# ----------------------------------------------------------------------
# LEFT COLUMN — Attacker Gateway Portal
# ----------------------------------------------------------------------
with left_col:
    st.subheader("🔐 Attacker Gateway Portal")
    st.caption("Simulated administrative login window — this is the exposed surface under inspection.")

    scenario = st.selectbox(
        "1-Click Exploit Payload",
        options=list(_DEMO_PAYLOADS.keys()),
        key="scenario_selector",
        help="Pick a pre-configured payload to instantly populate and fire the form.",
    )

    fire_now = scenario != "— Select a scenario —"
    payload = _DEMO_PAYLOADS[scenario]

    if st.session_state["is_compromised"]:
        st.error(
            "🚫 This session is ISOLATED. It has been routed into the deception sandbox and "
            "cannot reach genuine backend resources. Refresh the page to reset the demo.",
            icon="🚫",
        )

    with st.form("login_form", clear_on_submit=False):
        username_val = st.text_input(
            "Username",
            value=payload["username"] if fire_now else st.session_state["username_input"],
            disabled=st.session_state["is_compromised"],
        )
        password_val = st.text_input(
            "Password",
            value=payload["password"] if fire_now else st.session_state["password_input"],
            type="password",
            disabled=st.session_state["is_compromised"],
        )
        submitted = st.form_submit_button(
            "Sign In", disabled=st.session_state["is_compromised"], use_container_width=True
        )

    auto_fired = False
    if fire_now and scenario != st.session_state.get("_last_auto_fired_scenario"):
        auto_fired = True
        st.session_state["_last_auto_fired_scenario"] = scenario

    if (submitted or auto_fired) and not st.session_state["is_compromised"]:
        source_ip = _DEMO_SOURCE_IPS.get(scenario, "203.0.113.99")
        user_agent = _FAKE_USER_AGENTS.get(scenario, "Mozilla/5.0")
        st.session_state["username_input"] = username_val
        st.session_state["password_input"] = password_val
        _execute_login_attempt(username_val or payload["username"], password_val or payload["password"], source_ip, user_agent)
        st.rerun()

    st.divider()
    st.markdown("**Live attempt counter (this session):** " + str(st.session_state["login_attempts"]))

    if st.session_state["is_compromised"] and st.session_state["deception_records"]:
        st.subheader("📤 Exfiltrated Response Stream (Sinkholed)")
        st.caption(
            "The attacker's client believes it successfully dumped a customer table. "
            "Every row is synthetic. One row carries a hidden, traceable canary asset."
        )
        table_rows = [
            {
                "record_id": r.record_id,
                "full_name": r.full_name,
                "email": r.email,
                "account_token": r.account_token,
                "balance_usd": r.account_balance_usd,
                "card": r.masked_card_number,
                "⚠ canary": "★" if r.is_canary else "",
            }
            for r in st.session_state["deception_records"]
        ]
        st.dataframe(table_rows, use_container_width=True, height=280)

# ----------------------------------------------------------------------
# RIGHT COLUMN — SOC Console
# ----------------------------------------------------------------------
with right_col:
    st.subheader("🖥️ Security Operations Center Console")

    fingerprint = st.session_state["last_fingerprint"]
    band = fingerprint.threat_band if fingerprint else "GREEN"
    _render_threat_indicator(band)

    st.write("")
    metric_cols = st.columns(4)
    total_events = len(st.session_state["incident_log"])
    contained_events = sum(1 for e in st.session_state["incident_log"] if e.was_contained)
    current_risk = fingerprint.risk_score if fingerprint else 0
    canaries_deployed = sum(1 for r in st.session_state["deception_records"] if r.is_canary)

    metric_cols[0].metric("Total Events", total_events)
    metric_cols[1].metric("Contained", contained_events)
    metric_cols[2].metric("Current Risk Score", f"{current_risk}/100")
    metric_cols[3].metric("Canaries Deployed", canaries_deployed)

    st.write("")
    st.markdown("##### 🧬 Parsed Attacker Telemetry")
    if fingerprint:
        tel_cols = st.columns(2)
        with tel_cols[0]:
            st.text(f"Browser family:   {fingerprint.browser_family.value}")
            st.text(f"Device profile:   {fingerprint.device_profile.value}")
            st.text(f"OS / architecture: {fingerprint.os_architecture}")
        with tel_cols[1]:
            st.text(f"Automated agent:  {fingerprint.is_automated_agent}")
            st.text(f"Fingerprint ID:   {fingerprint.fingerprint_id}")
            st.text(f"Last classification: {st.session_state['last_verdict_label']}")
        with st.expander("Raw User-Agent string"):
            st.code(fingerprint.raw_user_agent or "(none captured yet)")
    else:
        st.caption("No telemetry captured yet — fire a scenario on the left to populate this panel.")

    st.write("")
    st.markdown("##### 📜 Historical Event Monitor")
    log_entries: List[IncidentLogEntry] = st.session_state["incident_log"]
    if log_entries:
        history_rows = [
            {
                "time (UTC)": e.iso_8601_timestamp,
                "source_ip": e.source_ip,
                "classification": e.threat_classification.value,
                "mitre": ", ".join(t.value for t in e.mitre_technique_ids) or "—",
                "risk": e.fingerprint.risk_score,
                "contained": e.was_contained,
            }
            for e in reversed(log_entries)
        ]
        st.dataframe(history_rows, use_container_width=True, height=240)
    else:
        st.caption("No events recorded yet in this session.")

    st.write("")
    st.markdown("##### 📄 Compliance Reporting")
    if log_entries:
        report_markdown = _generate_nist_report(log_entries)
        st.download_button(
            label="⬇️ Generate NIST SP 800-61 Compliance Report",
            data=report_markdown,
            file_name=f"phishtrap_incident_report_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.md",
            mime="text/markdown",
            use_container_width=True,
        )
        with st.expander("Preview report"):
            st.markdown(report_markdown)
    else:
        st.caption("Report generation unlocks once at least one event has been logged.")

st.divider()
with st.sidebar:
    st.markdown("### ⚙️ System Constants")
    st.text(f"THROTTLE_DELAY_DEFAULT = {CONFIG.THROTTLE_DELAY_DEFAULT}")
    st.text(f"RATE_LIMIT_CAP = {CONFIG.RATE_LIMIT_CAP}")
    st.text(f"CANARY_MARKER = {CONFIG.CANARY_MARKER}")
    st.divider()
    if st.button("🔄 Reset Demo Session", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
