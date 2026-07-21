"""
config.py
---------
Centralized Threat Signature Registry for PhishTrap AI.

Implements a thread-safe Singleton configuration object that owns every
compiled regular expression signature, system constant, and tunable
threshold used across the detection and deception pipeline. Signatures
are compiled exactly once at process start and reused everywhere, which
keeps the hot path (request inspection) allocation-free.
"""

from __future__ import annotations

import re
import threading
from typing import Final, Dict, List, Pattern


class _SingletonMeta(type):
    """
    Thread-safe Singleton metaclass.

    A double-checked locking pattern is used so that the (rare) lock
    acquisition only happens on the very first instantiation. Every
    subsequent call is a simple dictionary lookup, so the Singleton
    carries effectively zero overhead once warmed up.
    """

    _instances: Dict[type, "PhishTrapConfig"] = {}
    _lock: threading.Lock = threading.Lock()

    def __call__(cls, *args: object, **kwargs: object) -> "PhishTrapConfig":
        if cls not in cls._instances:
            with cls._lock:
                if cls not in cls._instances:
                    instance = super().__call__(*args, **kwargs)
                    cls._instances[cls] = instance
        return cls._instances[cls]


class PhishTrapConfig(metaclass=_SingletonMeta):
    """
    Immutable-by-convention configuration Singleton.

    All attributes are declared `Final` to signal (and, under static
    type-checking, enforce) that this object is read-only after
    construction. Consumers should never mutate signature lists at
    runtime; if new signatures are needed, extend this class and
    re-deploy.
    """

    # ------------------------------------------------------------------
    # System-wide constants (contract values — do not rename or retype)
    # ------------------------------------------------------------------
    THROTTLE_DELAY_DEFAULT: Final[float] = 0.05
    RATE_LIMIT_CAP: Final[int] = 5
    CANARY_MARKER: Final[str] = "X-TRAP-CANARY-ALPHA"

    # ------------------------------------------------------------------
    # Risk scoring weights
    # ------------------------------------------------------------------
    RISK_WEIGHT_SQLI: Final[int] = 40
    RISK_WEIGHT_XSS: Final[int] = 35
    RISK_WEIGHT_BRUTE_FORCE: Final[int] = 25
    RISK_WEIGHT_AUTOMATED_AGENT: Final[int] = 20
    RISK_SCORE_MAX: Final[int] = 100
    RISK_SCORE_MIN: Final[int] = 0

    # ------------------------------------------------------------------
    # Threat-level bands (used to drive the SOC console's traffic-light UI)
    # ------------------------------------------------------------------
    THREAT_BAND_GREEN_MAX: Final[int] = 24
    THREAT_BAND_ORANGE_MAX: Final[int] = 64
    # anything above THREAT_BAND_ORANGE_MAX is RED

    def __init__(self) -> None:
        self._sqli_patterns: Final[List[Pattern[str]]] = self._compile_sqli_signatures()
        self._xss_patterns: Final[List[Pattern[str]]] = self._compile_xss_signatures()
        self._brute_force_patterns: Final[List[Pattern[str]]] = self._compile_brute_force_signatures()
        self._automated_agent_patterns: Final[List[Pattern[str]]] = self._compile_automated_agent_signatures()
        self._known_breached_credentials: Final[frozenset[str]] = frozenset(
            {
                "admin:admin",
                "admin:password",
                "admin:123456",
                "root:root",
                "root:toor",
                "administrator:letmein",
                "test:test",
                "guest:guest",
                "admin:qwerty",
                "admin:admin123",
            }
        )

    # ------------------------------------------------------------------
    # Signature compilation blocks
    # ------------------------------------------------------------------
    @staticmethod
    def _compile_sqli_signatures() -> List[Pattern[str]]:
        """OWASP A03:2021 (Injection) — SQLi mutation coverage."""
        raw_patterns: List[str] = [
            r"(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)",  # quote / comment injection markers
            r"(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # '=' followed by terminator
            r"(?i)\bor\b\s+\d+\s*=\s*\d+",  # classic tautology: OR 1=1
            r"(?i)\band\b\s+\d+\s*=\s*\d+",  # tautology variant: AND 1=1
            r"(?i)union(\s|/\*.*?\*/|\+|\%20)+select",  # UNION SELECT, whitespace/comment obfuscated
            r"(?i)/\*.*?\*/",  # inline SQL comment block used to split keywords
            r"(?i)0x[0-9a-f]{4,}",  # hex-encoded payload fragments
            r"(?i)\b(select|insert|update|delete|drop|alter)\b.{0,40}\b(from|into|table|database)\b",
            r"(?i)waitfor\s+delay\s+'?\d",  # time-based blind SQLi
            r"(?i)sleep\(\s*\d+\s*\)",  # MySQL time-based blind SQLi
            r"(?i)benchmark\(\s*\d+\s*,",  # MySQL benchmark-based blind SQLi
            r"(?i);\s*(drop|shutdown|exec)\b",  # stacked query abuse
            r"(?i)information_schema",  # schema enumeration
            r"(?i)xp_cmdshell",  # MSSQL command execution
        ]
        return [re.compile(pattern) for pattern in raw_patterns]

    @staticmethod
    def _compile_xss_signatures() -> List[Pattern[str]]:
        """OWASP A03:2021 (Injection) — XSS / DOM mutation coverage."""
        raw_patterns: List[str] = [
            r"(?i)<\s*script[^>]*>",  # direct <script> tag
            r"(?i)<\s*/\s*script\s*>",  # closing tag fragment (polymorphic split payloads)
            r"(?i)on(load|error|click|mouseover|focus|blur|submit|change)\s*=",  # event-handler injection
            r"(?i)javascript\s*:",  # javascript: URI scheme
            r"(?i)<\s*img[^>]+src\s*=\s*[^>]*onerror",  # img onerror vector
            r"(?i)<\s*iframe[^>]*>",  # iframe injection
            r"(?i)<\s*svg[^>]*on\w+\s*=",  # SVG event-handler vector
            r"(?i)document\.(cookie|location|write)",  # DOM sink access
            r"(?i)eval\s*\(",  # dynamic code execution sink
            r"(?i)&#x[0-9a-f]+;",  # hex HTML entity obfuscation
            r"(?i)%3Cscript",  # URL-encoded <script
            r"(?i)String\.fromCharCode\(",  # charcode obfuscated payload construction
        ]
        return [re.compile(pattern) for pattern in raw_patterns]

    @staticmethod
    def _compile_brute_force_signatures() -> List[Pattern[str]]:
        """OWASP A07:2021 (Identification & Authentication Failures)."""
        raw_patterns: List[str] = [
            r"(?i)^(admin|administrator|root|test|guest|user)$",  # dictionary usernames
            r"(?i)^(password|123456|qwerty|letmein|admin123|toor|changeme)$",  # dictionary passwords
            r"(?i)^\d{4,8}$",  # numeric-only credential (pin-style brute force)
        ]
        return [re.compile(pattern) for pattern in raw_patterns]

    @staticmethod
    def _compile_automated_agent_signatures() -> List[Pattern[str]]:
        """Heuristics for scripted / automated client detection."""
        raw_patterns: List[str] = [
            r"(?i)python-requests",
            r"(?i)curl/",
            r"(?i)wget/",
            r"(?i)sqlmap",
            r"(?i)nikto",
            r"(?i)nmap",
            r"(?i)hydra",
            r"(?i)burpsuite",
            r"(?i)go-http-client",
            r"(?i)headlesschrome",
            r"(?i)phantomjs",
            r"(?i)^\s*$",  # empty user-agent string
        ]
        return [re.compile(pattern) for pattern in raw_patterns]

    # ------------------------------------------------------------------
    # Public read-only accessors
    # ------------------------------------------------------------------
    @property
    def sqli_patterns(self) -> List[Pattern[str]]:
        return list(self._sqli_patterns)

    @property
    def xss_patterns(self) -> List[Pattern[str]]:
        return list(self._xss_patterns)

    @property
    def brute_force_patterns(self) -> List[Pattern[str]]:
        return list(self._brute_force_patterns)

    @property
    def automated_agent_patterns(self) -> List[Pattern[str]]:
        return list(self._automated_agent_patterns)

    @property
    def known_breached_credentials(self) -> frozenset[str]:
        return self._known_breached_credentials

    def classify_threat_band(self, risk_score: int) -> str:
        """Map a numeric risk score onto a traffic-light threat band."""
        if risk_score <= self.THREAT_BAND_GREEN_MAX:
            return "GREEN"
        if risk_score <= self.THREAT_BAND_ORANGE_MAX:
            return "ORANGE"
        return "RED"


# Module-level convenience accessor — importing this is the intended
# way for other modules to reach the Singleton instance.
def get_config() -> PhishTrapConfig:
    return PhishTrapConfig()
