"""
generator.py
------------
Memory-Optimized Dynamic Data Factory for PhishTrap AI.

`DeceptionDataFactory` streams synthetic customer records to a
"leaking" attacker one row at a time using a pure Python generator.
Because it `yield`s rather than materializing a list, the runtime
memory footprint stays O(1) regardless of how many thousands of rows
an automated scraper requests — the attacker's client, not this
server, bears the accumulation cost.

Two deception mechanisms are layered in:

  1. A hidden canary token — a single record, inserted at a random
     index in the stream, that is styled to look like a live API key
     or crypto wallet address but is in fact permanently traceable via
     `PhishTrapConfig.CANARY_MARKER`. If this value is ever replayed
     back at the system (or observed elsewhere), it proves the
     attacker exfiltrated and used the sinkholed data.
  2. A non-blocking per-row throttle that is large enough to waste an
     automated scanner's connection/clock budget, but far too small to
     be noticeable to a human operator glancing at the SOC console.
"""

from __future__ import annotations

import random
import time
from typing import Generator, Optional

from faker import Faker

from config import PhishTrapConfig, get_config
from exceptions import DataSynthesisFailure, mask_internal_errors
from models import SyntheticCustomerRecord


class DeceptionDataFactory:
    """Streams believable-but-entirely-fake customer records."""

    def __init__(self, config: Optional[PhishTrapConfig] = None, seed: Optional[int] = None) -> None:
        self._config: PhishTrapConfig = config or get_config()
        self._faker: Faker = Faker()
        if seed is not None:
            Faker.seed(seed)
            random.seed(seed)

    # ------------------------------------------------------------------
    # Record builders
    # ------------------------------------------------------------------
    @mask_internal_errors(fallback_exception=DataSynthesisFailure)
    def _build_filler_record(self) -> SyntheticCustomerRecord:
        card_last_four = f"{random.randint(0, 9999):04d}"
        card_first_four = f"{random.randint(0, 9999):04d}"
        return SyntheticCustomerRecord(
            full_name=self._faker.name(),
            email=self._faker.free_email(),
            account_token=self._faker.sha256()[:32],
            account_balance_usd=round(random.uniform(12.50, 98_450.00), 2),
            masked_card_number=f"{card_first_four}-****-****-{card_last_four}",
            is_canary=False,
        )

    @mask_internal_errors(fallback_exception=DataSynthesisFailure)
    def _build_canary_record(self) -> SyntheticCustomerRecord:
        """
        Build the single tracking asset for this stream. It is
        disguised as a high-value enterprise API credential so that an
        attacker scraping the feed is drawn to copy/exfiltrate it
        specifically. The `CANARY_MARKER` constant is embedded directly
        inside the token so any downstream sighting of this string is
        an unambiguous signal of compromise.
        """
        marker = self._config.CANARY_MARKER
        disguised_token = f"sk_live_{marker}_{self._faker.sha256()[:24]}"
        return SyntheticCustomerRecord(
            full_name="Enterprise Service Account",
            email=f"svc-billing-prod@{self._faker.domain_name()}",
            account_token=disguised_token,
            account_balance_usd=round(random.uniform(250_000.00, 999_999.00), 2),
            masked_card_number="4111-****-****-0007",
            is_canary=True,
        )

    # ------------------------------------------------------------------
    # Streaming generator
    # ------------------------------------------------------------------
    def stream_records(
        self,
        total_records: int,
        *,
        throttle_seconds: Optional[float] = None,
        inject_canary: bool = True,
    ) -> Generator[SyntheticCustomerRecord, None, None]:
        """
        Yield `total_records` synthetic rows one at a time.

        Args:
            total_records: number of rows the caller (attacker) requested.
            throttle_seconds: per-row delay; defaults to
                PhishTrapConfig.THROTTLE_DELAY_DEFAULT. Pass 0.0 to
                disable throttling (e.g. for internal, trusted admin
                previews where wasting time serves no purpose).
            inject_canary: whether to embed the hidden tracking asset.
                Always True in a real containment scenario; exposed as
                a parameter purely for isolated unit testing.
        """
        if total_records <= 0:
            raise DataSynthesisFailure(
                internal_detail=f"stream_records called with non-positive total_records={total_records}",
                public_message="Invalid record count requested.",
            )

        delay = self._config.THROTTLE_DELAY_DEFAULT if throttle_seconds is None else throttle_seconds
        canary_index = random.randint(0, total_records - 1) if inject_canary else -1

        for index in range(total_records):
            if index == canary_index:
                yield self._build_canary_record()
            else:
                yield self._build_filler_record()

            if delay > 0:
                time.sleep(delay)

    def materialize(
        self,
        total_records: int,
        *,
        throttle_seconds: Optional[float] = None,
        inject_canary: bool = True,
    ) -> list[SyntheticCustomerRecord]:
        """
        Convenience wrapper for callers (like the Streamlit UI) that
        need a concrete list for immediate rendering rather than a
        lazy stream. Still built on top of the O(1)-memory generator;
        the list materialization cost is the caller's explicit choice.
        """
        return list(
            self.stream_records(
                total_records,
                throttle_seconds=throttle_seconds,
                inject_canary=inject_canary,
            )
        )
