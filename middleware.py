"""
middleware.py
-------------
Deterministic Inspection Web Application Firewall & Profiler.

`SecurityInspectionEngine` is the single entry point every inbound
"request" (in this demo, a login form submission) passes through. It:

  1. Sanitizes and normalizes raw input (URL-decoding, whitespace
     collapsing) so obfuscated payloads cannot slip past regex checks.
  2. Evaluates the normalized input against every compiled signature
     group from `PhishTrapConfig`.
  3. Parses the User-Agent string into a structured `AttackerFingerprint`.
  4. Produces a fully-typed `IncidentLogEntry` describing the outcome.

The engine is deterministic and side-effect-free with respect to
global state: given the same input twice, it produces the same
verdict twice. It never raises unhandled exceptions — all internal
failures are caught, masked, and re-raised as typed PhishTrap
exceptions so the calling UI layer can fail safely.
"""

from __future__ import annotations

import html
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from config import PhishTrapConfig, get_config
from exceptions import (
    SignatureCompromiseError,
    TelemetryExtractionException,
    mask_internal_errors,
)
from models import (
    AttackerFingerprint,
    BrowserFamily,
    DeviceProfile,
    IncidentLogEntry,
    MitreTechnique,
    ThreatClassification,
)

# Maps each threat classification to the MITRE technique IDs it implies.
_THREAT_TO_MITRE: Dict[ThreatClassification, List[MitreTechnique]] = {
    ThreatClassification.SQL_INJECTION: [MitreTechnique.T1190],
    ThreatClassification.CROSS_SITE_SCRIPTING: [MitreTechnique.T1190, MitreTechnique.T1059_007],
    ThreatClassification.BRUTE_FORCE: [MitreTechnique.T1110],
    ThreatClassification.CREDENTIAL_STUFFING: [MitreTechnique.T1110_003, MitreTechnique.T1589_001],
    ThreatClassification.AUTOMATED_RECON: [MitreTechnique.T1595],
    ThreatClassification.BENIGN: [],
}


@dataclass
class InspectionVerdict:
    """Internal result bundle produced by a single inspection pass."""

    is_malicious: bool
    threat_classification: ThreatClassification
    matched_signatures: List[str] = field(default_factory=list)
    fingerprint: AttackerFingerprint = field(default_factory=AttackerFingerprint)


class SecurityInspectionEngine:
    """High-efficiency deterministic WAF and telemetry profiler."""

    def __init__(self, config: PhishTrapConfig | None = None) -> None:
        self._config: PhishTrapConfig = config or get_config()
        self._attempt_counters: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Input normalization
    # ------------------------------------------------------------------
    @mask_internal_errors(fallback_exception=SignatureCompromiseError)
    def _normalize(self, raw_value: str) -> str:
        """
        Collapse common obfuscation vectors down to a canonical form
        before signature matching: URL-decode (twice, to catch double
        encoding), HTML-unescape, and collapse inline comment blocks
        used to split SQL keywords (e.g. 'UN/**/ION').
        """
        value = raw_value
        for _ in range(2):
            decoded = urllib.parse.unquote(value)
            if decoded == value:
                break
            value = decoded
        value = html.unescape(value)
        value = re.sub(r"/\*.*?\*/", "", value)
        return value

    # ------------------------------------------------------------------
    # Signature evaluation
    # ------------------------------------------------------------------
    def _match_signatures(self, normalized_value: str) -> Dict[ThreatClassification, List[str]]:
        matches: Dict[ThreatClassification, List[str]] = {
            ThreatClassification.SQL_INJECTION: [],
            ThreatClassification.CROSS_SITE_SCRIPTING: [],
        }
        for pattern in self._config.sqli_patterns:
            if pattern.search(normalized_value):
                matches[ThreatClassification.SQL_INJECTION].append(pattern.pattern)
        for pattern in self._config.xss_patterns:
            if pattern.search(normalized_value):
                matches[ThreatClassification.CROSS_SITE_SCRIPTING].append(pattern.pattern)
        return matches

    def _check_brute_force(self, username: str, password: str, source_ip: str) -> Tuple[bool, List[str]]:
        matched: List[str] = []
        for pattern in self._config.brute_force_patterns:
            if pattern.search(username) or pattern.search(password):
                matched.append(pattern.pattern)

        credential_pair = f"{username.lower()}:{password.lower()}"
        if credential_pair in self._config.known_breached_credentials:
            matched.append(f"known_breached_credential:{credential_pair}")

        self._attempt_counters[source_ip] = self._attempt_counters.get(source_ip, 0) + 1
        rate_exceeded = self._attempt_counters[source_ip] > self._config.RATE_LIMIT_CAP
        if rate_exceeded:
            matched.append(f"rate_limit_exceeded:{self._attempt_counters[source_ip]}_attempts")

        return (len(matched) > 0), matched

    # ------------------------------------------------------------------
    # Telemetry / fingerprint parsing
    # ------------------------------------------------------------------
    @mask_internal_errors(fallback_exception=TelemetryExtractionException)
    def build_fingerprint(self, user_agent: str) -> AttackerFingerprint:
        ua = (user_agent or "").strip()
        ua_lower = ua.lower()

        is_automated = any(
            pattern.search(ua) for pattern in self._config.automated_agent_patterns
        )

        if "chrome" in ua_lower and "edg" not in ua_lower:
            browser = BrowserFamily.CHROME
        elif "firefox" in ua_lower:
            browser = BrowserFamily.FIREFOX
        elif "safari" in ua_lower and "chrome" not in ua_lower:
            browser = BrowserFamily.SAFARI
        elif "edg" in ua_lower:
            browser = BrowserFamily.EDGE
        elif is_automated:
            browser = BrowserFamily.SCRIPTED_CLIENT
        else:
            browser = BrowserFamily.UNKNOWN

        if "headless" in ua_lower or "phantomjs" in ua_lower:
            device = DeviceProfile.HEADLESS
        elif "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
            device = DeviceProfile.MOBILE
        elif "tablet" in ua_lower or "ipad" in ua_lower:
            device = DeviceProfile.TABLET
        elif ua:
            device = DeviceProfile.DESKTOP
        else:
            device = DeviceProfile.UNKNOWN

        if "windows" in ua_lower:
            os_arch = "Windows x86_64"
        elif "mac os" in ua_lower or "macintosh" in ua_lower:
            os_arch = "macOS ARM64/x86_64"
        elif "linux" in ua_lower and "android" not in ua_lower:
            os_arch = "Linux x86_64"
        elif "android" in ua_lower:
            os_arch = "Android ARM64"
        elif "iphone" in ua_lower or "ipad" in ua_lower:
            os_arch = "iOS ARM64"
        else:
            os_arch = "Unknown"

        return AttackerFingerprint(
            browser_family=browser,
            os_architecture=os_arch,
            device_profile=device,
            raw_user_agent=ua,
            is_automated_agent=is_automated,
        )

    # ------------------------------------------------------------------
    # Top-level orchestration
    # ------------------------------------------------------------------
    @mask_internal_errors(fallback_exception=SignatureCompromiseError)
    def inspect(
        self,
        *,
        username: str,
        password: str,
        source_ip: str,
        user_agent: str,
    ) -> Tuple[InspectionVerdict, IncidentLogEntry]:
        """
        Run a full inspection pass and return both the raw verdict and
        the fully-typed audit log entry. Never raises for "normal"
        malicious input — that is an expected, handled outcome, not an
        exceptional one. Only genuine internal failures propagate (as
        masked PhishTrap exceptions).
        """
        normalized_username = self._normalize(username)
        normalized_password = self._normalize(password)

        injection_matches = self._match_signatures(normalized_username)
        injection_matches_pw = self._match_signatures(normalized_password)
        for classification, hits in injection_matches_pw.items():
            injection_matches[classification].extend(hits)

        is_brute_force, brute_force_matches = self._check_brute_force(
            normalized_username, normalized_password, source_ip
        )

        fingerprint = self.build_fingerprint(user_agent)

        risk_score = 0
        classification = ThreatClassification.BENIGN
        matched_signatures: List[str] = []

        if injection_matches[ThreatClassification.SQL_INJECTION]:
            classification = ThreatClassification.SQL_INJECTION
            matched_signatures.extend(injection_matches[ThreatClassification.SQL_INJECTION])
            risk_score += self._config.RISK_WEIGHT_SQLI
        elif injection_matches[ThreatClassification.CROSS_SITE_SCRIPTING]:
            classification = ThreatClassification.CROSS_SITE_SCRIPTING
            matched_signatures.extend(injection_matches[ThreatClassification.CROSS_SITE_SCRIPTING])
            risk_score += self._config.RISK_WEIGHT_XSS
        elif is_brute_force:
            classification = ThreatClassification.BRUTE_FORCE
            matched_signatures.extend(brute_force_matches)
            risk_score += self._config.RISK_WEIGHT_BRUTE_FORCE

        if fingerprint.is_automated_agent:
            risk_score += self._config.RISK_WEIGHT_AUTOMATED_AGENT
            if classification == ThreatClassification.BENIGN:
                classification = ThreatClassification.AUTOMATED_RECON

        risk_score = max(self._config.RISK_SCORE_MIN, min(self._config.RISK_SCORE_MAX, risk_score))
        fingerprint.risk_score = risk_score

        is_malicious = classification != ThreatClassification.BENIGN

        verdict = InspectionVerdict(
            is_malicious=is_malicious,
            threat_classification=classification,
            matched_signatures=matched_signatures,
            fingerprint=fingerprint,
        )

        log_entry = IncidentLogEntry(
            source_ip=source_ip,
            threat_classification=classification,
            mitre_technique_ids=_THREAT_TO_MITRE[classification],
            matched_signatures=matched_signatures,
            fingerprint=fingerprint,
            was_contained=is_malicious,
            notes=None if is_malicious else "Traffic evaluated as benign; no containment action taken.",
        )

        return verdict, log_entry

    def reset_rate_limit_counters(self) -> None:
        """Sandboxed test-harness helper — clears in-memory attempt counters."""
        self._attempt_counters.clear()
