"""Fault injection manager for Mock PSP.

Implements test-only fault scenarios per docs/modules/04-policy-and-payments.md §9.3.
"""

from typing import Any

from mock_psp.schemas import PspFaultItem


class FaultManager:
    """Manages active simulated payment faults."""

    def __init__(self) -> None:
        self._faults: list[dict[str, Any]] = []

    def configure_faults(
        self,
        faults: list[PspFaultItem],
        merchant_id: str | None = None,
    ) -> None:
        """Register faults with optional merchant scoping."""
        for f in faults:
            self._faults.append(
                {
                    "merchant_id": merchant_id,
                    "type": f.type,
                    "probability": f.probability if f.probability is not None else 1.0,
                    "count": f.count if f.count is not None else 1,
                    "decline_code": f.decline_code or "SIMULATED_DECLINE",
                }
            )

    def clear(self) -> None:
        """Reset all configured faults."""
        self._faults.clear()

    def get_fault(self, fault_type: str, merchant_id: str | None = None) -> dict[str, Any] | None:
        """Find matching fault if available and decrement its count."""
        for idx, f in enumerate(self._faults):
            if f["type"] == fault_type:
                if f["merchant_id"] is None or f["merchant_id"] == merchant_id:
                    # Found active fault
                    count = f["count"]
                    if count <= 1:
                        return self._faults.pop(idx)
                    f["count"] = count - 1
                    return dict(f)
        return None
