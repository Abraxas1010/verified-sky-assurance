"""Data models for the SKY proof checker service."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Obligation:
    """A single proof obligation in a bundle."""
    id: str
    kind: str = "check"  # "check" | "whnf" | "defeq" | "infer"
    compiled_check: Any = None  # Combinator tree (JSON)
    fuel: int = 10000
    fuel_reduce: int = 50000
    expected_result: str = "true"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ObligationResult:
    """Result of verifying a single obligation."""
    id: str
    checked: bool
    steps_used: int = 0
    decoded: Any = None
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class StarkAttestation:
    """STARK attestation for a verification run."""
    type: str = "stark"
    proof: str = ""  # base64-encoded STARK proof
    public_inputs: str = ""  # hex hash of obligations + results
    trace_length: int = 0
    security_bits: int = 128

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Bundle:
    """A complete SKY proof bundle."""
    version: str = "1.0.0"
    format: str = "sky-bundle"
    source_hash: str = ""
    description: str = ""
    obligations: list[Obligation] = field(default_factory=list)
    result: dict = field(default_factory=dict)
    attestation: dict | None = None

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "format": self.format,
            "source_hash": self.source_hash,
            "description": self.description,
            "obligations": [o.to_dict() for o in self.obligations],
            "result": self.result,
            "attestation": self.attestation,
        }

    @staticmethod
    def from_dict(d: dict) -> Bundle:
        return Bundle(
            version=d.get("version", "1.0.0"),
            format=d.get("format", "sky-bundle"),
            source_hash=d.get("source_hash", ""),
            description=d.get("description", ""),
            obligations=[
                Obligation(**o) for o in d.get("obligations", [])
            ],
            result=d.get("result", {}),
            attestation=d.get("attestation"),
        )


@dataclass
class CompileRequest:
    """Request to compile Lean source to SKY bundle."""
    source: str
    fuel: int = 10000
    fuel_reduce: int = 50000
    with_attestation: bool = False


@dataclass
class VerifyRequest:
    """Request to verify an SKY bundle."""
    bundle: dict
    with_attestation: bool = False


@dataclass
class ServiceStatus:
    """Service health status."""
    version: str
    status: str  # "ready" | "degraded" | "offline"
    lean_repl_available: bool = False
    stark_prover_available: bool = False
    reducer_version: str = "1.0.0"
