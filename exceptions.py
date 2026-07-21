"""
exceptions.py
-------------
Enterprise Fault Isolation Layer for PhishTrap AI.

Every exception raised anywhere in the PhishTrap stack derives from
`PhishTrapException`. Each subclass is domain-specific so callers can
catch precisely what they expect, while a masking decorator ensures
that no internal stack trace, file path, or schema name is ever
allowed to leak into a public-facing (Streamlit) response.
"""

from __future__ import annotations

import functools
import logging
import uuid
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger("phishtrap.exceptions")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    )
    logger.addHandler(_handler)

_F = TypeVar("_F", bound=Callable[..., Any])


class PhishTrapException(Exception):
    """
    Base exception for the entire PhishTrap AI system.

    Carries an `incident_id` so that operators can correlate a
    user-facing generic error message with the fully detailed,
    privately logged traceback.
    """

    public_message: str = "An internal containment error occurred. The event has been logged."

    def __init__(self, internal_detail: str, *, public_message: Optional[str] = None) -> None:
        self.incident_id: str = uuid.uuid4().hex[:12]
        self.internal_detail: str = internal_detail
        if public_message is not None:
            self.public_message = public_message
        super().__init__(internal_detail)
        logger.error(
            "incident_id=%s exception=%s detail=%s",
            self.incident_id,
            self.__class__.__name__,
            self.internal_detail,
        )

    def to_safe_response(self) -> str:
        """Return only what is safe to render to an untrusted client."""
        return f"[{self.__class__.__name__}] {self.public_message} (ref: {self.incident_id})"


class SignatureCompromiseError(PhishTrapException):
    """
    Raised when the SecurityInspectionEngine detects that an inbound
    payload matches one or more compiled attack signatures, or when
    the signature registry itself fails to evaluate safely.
    """

    public_message = "Request rejected by inspection policy."


class DataSynthesisFailure(PhishTrapException):
    """
    Raised when the DeceptionDataFactory cannot safely generate or
    stream a synthetic record (e.g. Faker/Pydantic validation failure
    inside the generator pipeline).
    """

    public_message = "Unable to complete the requested operation at this time."


class IsolationSandboxBreach(PhishTrapException):
    """
    Raised when a session that has been marked as compromised attempts
    to access a genuine (non-sandboxed) system resource or function.
    This is a hard-stop condition — it should never be silently
    swallowed by calling code.
    """

    public_message = "Session isolated. This action is not permitted."


class TelemetryExtractionException(PhishTrapException):
    """
    Raised when attacker fingerprint / telemetry parsing fails, e.g.
    a malformed or hostile User-Agent string that cannot be safely
    decomposed into an AttackerFingerprint model.
    """

    public_message = "Telemetry could not be processed."


def mask_internal_errors(
    fallback_exception: type[PhishTrapException] = PhishTrapException,
    public_message: Optional[str] = None,
) -> Callable[[_F], _F]:
    """
    Decorator that catches *any* unexpected exception raised inside
    the wrapped function, re-raises it as a typed PhishTrap exception,
    and guarantees the original traceback (which may reference
    internal file paths, variable names, or schema details) never
    propagates to the caller. The full original error is preserved
    only in the server-side log via `PhishTrapException.__init__`.
    """

    def decorator(func: _F) -> _F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except PhishTrapException:
                # Already a typed, safely-masked exception — let it propagate.
                raise
            except Exception as exc:  # noqa: BLE001 - intentional broad catch at the boundary
                raise fallback_exception(
                    internal_detail=f"{func.__qualname__} failed: {exc!r}",
                    public_message=public_message,
                ) from None  # `from None` suppresses chained traceback leakage

        return wrapper  # type: ignore[return-value]

    return decorator
