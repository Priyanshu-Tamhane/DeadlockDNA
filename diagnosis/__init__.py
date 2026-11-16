"""
diagnosis — DeadlockDNA Diagnosis & Explainability Subsystem (Feature A)
"""

from .explainer import (
    DeadlockExplainer,
    DiagnosisResult,
    DiagnosisStep,
    Confidence,
    EvidenceStatus,
)

__all__ = [
    "DeadlockExplainer",
    "DiagnosisResult",
    "DiagnosisStep",
    "Confidence",
    "EvidenceStatus",
]
