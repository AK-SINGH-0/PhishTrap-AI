"""
models.py
---------
Strict, type-safe data contracts for PhishTrap AI, built on Pydantic v2.

These models are the only shapes allowed to cross module boundaries in
the system: raw dicts are parsed into these models as early as
possible, and every downstream component (middleware, generator, UI)
consumes typed instances rather than loose dictionaries.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
)


class ThreatClassification(str, Enum):
    """Coarse-grained attack category, aligned to the config signature groups."""

    SQL_INJECTION = "SQL_INJECTION"
    CROSS_SITE_SCRIPTING = "CROSS_SITE_SCRIPTING"
    BRUTE_FORCE = "BRUTE_FORCE"
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"
    AUTOMATED_RECON = "AUTOMATED_RECON"
    BENIGN = "BENIGN"


class MitreTechnique(str, Enum):
    """Subset of MITRE ATT&CK technique IDs relevant to this tool's scope."""

    T1190 = "T1190"  # Exploit Public-Facing Application
    T1110 = "T1110"  # Brute Force
    T1110_003 = "T1110.003"  # Password Spraying
    T1059_007 = "T1059.007"  # Command and Scripting Interpreter: JavaScript
    T1595 = "T1595"  # Active Scanning
    T1589_001 = "T1589.001"  # Gather Victim Identity Info: Credentials


class BrowserFamily(str, Enum):
    CHROME = "Chrome"
    FIREFOX = "Firefox"
    SAFARI = "Safari"
    EDGE = "Edge"
    SCRIPTED_CLIENT = "Scripted-Client"
    UNKNOWN = "Unknown"


class DeviceProfile(str, Enum):
    DESKTOP = "Desktop"
    MOBILE = "Mobile"
    TABLET = "Tablet"
    HEADLESS = "Headless"
    UNKNOWN = "Unknown"


class AttackerFingerprint(BaseModel):
    """
    Structured telemetry profile derived from an inbound request's
    headers and User-Agent string. `risk_score` is deliberately a
    settable field (not purely computed) because the
    SecurityInspectionEngine accumulates it incrementally as each
    signature group is evaluated; `threat_band` is derived from it.
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    fingerprint_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    browser_family: BrowserFamily = Field(default=BrowserFamily.UNKNOWN)
    os_architecture: str = Field(default="Unknown", max_length=64)
    device_profile: DeviceProfile = Field(default=DeviceProfile.UNKNOWN)
    raw_user_agent: str = Field(default="", max_length=1024)
    is_automated_agent: bool = Field(default=False)
    risk_score: int = Field(default=0, ge=0, le=100)

    @field_validator("raw_user_agent")
    @classmethod
    def _strip_control_characters(cls, value: str) -> str:
        return "".join(ch for ch in value if ch.isprintable())

    @computed_field  # type: ignore[misc]
    @property
    def threat_band(self) -> str:
        if self.risk_score <= 24:
            return "GREEN"
        if self.risk_score <= 64:
            return "ORANGE"
        return "RED"


class IncidentLogEntry(BaseModel):
    """
    A single, immutable audit-trail record of a detected (or cleared)
    inspection event. This is the atomic unit that gets aggregated
    into the NIST SP 800-61 compliance report.
    """

    model_config = ConfigDict(validate_assignment=True)

    incident_id: str = Field(default_factory=lambda: uuid4().hex[:12])
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str = Field(..., description="Ingress source IP address of the request")
    threat_classification: ThreatClassification
    mitre_technique_ids: List[MitreTechnique] = Field(default_factory=list)
    matched_signatures: List[str] = Field(default_factory=list)
    fingerprint: AttackerFingerprint
    was_contained: bool = Field(default=False)
    notes: Optional[str] = Field(default=None, max_length=500)

    @field_validator("source_ip")
    @classmethod
    def _validate_ip_shape(cls, value: str) -> str:
        octets = value.split(".")
        if len(octets) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            raise ValueError("source_ip must be a syntactically valid IPv4 address")
        return value

    @computed_field  # type: ignore[misc]
    @property
    def iso_8601_timestamp(self) -> str:
        return self.timestamp_utc.isoformat().replace("+00:00", "Z")


class SyntheticCustomerRecord(BaseModel):
    """
    A fabricated customer entity streamed out by the DeceptionDataFactory.
    Every field is synthetic (Faker-derived); nothing here ever
    corresponds to a real customer, real account, or real credential.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    record_id: str = Field(default_factory=lambda: uuid4().hex[:10])
    full_name: str = Field(..., max_length=128)
    email: str = Field(..., max_length=254)
    account_token: str = Field(..., min_length=8, max_length=128)
    account_balance_usd: float = Field(..., ge=0)
    masked_card_number: str = Field(..., pattern=r"^\d{4}-\*{4}-\*{4}-\d{4}$")
    is_canary: bool = Field(
        default=False,
        description="True if this record is the injected tracking asset rather than filler data.",
    )

    @field_validator("email")
    @classmethod
    def _basic_email_shape(cls, value: str) -> str:
        if "@" not in value or "." not in value.split("@")[-1]:
            raise ValueError("email must contain '@' and a domain with a dot")
        return value
