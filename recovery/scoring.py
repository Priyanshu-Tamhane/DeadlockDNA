"""
recovery/scoring.py — Heuristic Scoring Engine for Recovery Candidates (Feature E)

Calculates transparent, interpretable scores for recovery candidates using documented weights
as specified in Section 7 of the Feature Expansion Specification.
"""

from dataclasses import dataclass
from typing import List, Optional

from .candidate import RecoveryCandidate, CandidateFactors, ActionType


@dataclass(frozen=True)
class ScoringConfig:
    """
    Documented heuristic weights for transparent recovery ranking.

    Score range:
      Maximum (all positive factors = 1.0, all penalties = 0.0): +0.80
      Minimum (all positive factors = 0.0, all penalties = 1.0): -0.35

    Positive weights sum: 0.35 + 0.30 + 0.15 = 0.80
    Penalty weights:      0.15 + 0.20 = 0.35 (capped to keep min score reasonable)
    """
    w_disposability: float = 0.35          # Value of disposable test execution
    w_cooperative_support: float = 0.30    # Value of clean cooperative shutdown/signal support
    w_reversibility: float = 0.15          # Value of non-destructive actions (alerting, cooperative cancels)
    w_state_loss: float = 0.15             # Penalty for lost in-flight work or dirty state
    w_criticality: float = 0.20            # Penalty for disrupting production applications


DEFAULT_SCORING_CONFIG = ScoringConfig()


def calculate_score(factors: CandidateFactors, config: ScoringConfig = DEFAULT_SCORING_CONFIG) -> float:
    """
    Computes a transparent, normalized recovery score.
    Formula:
        score = (w_disp * test_disposability)
              + (w_coop * cooperative_shutdown_support)
              + (w_rev  * reversibility)
              - (w_loss * estimated_state_loss)
              - (w_crit * application_criticality)
    """
    raw_score = (
        (config.w_disposability * factors.test_disposability)
        + (config.w_cooperative_support * factors.cooperative_shutdown_support)
        + (config.w_reversibility * factors.reversibility)
        - (config.w_state_loss * factors.estimated_state_loss)
        - (config.w_criticality * factors.application_criticality)
    )
    return raw_score


def generate_ranking_rationale(candidate: RecoveryCandidate, config: ScoringConfig = DEFAULT_SCORING_CONFIG) -> str:
    """Produces a plain-text rationale explaining the score components."""
    if not candidate.is_eligible:
        return f"Ineligible for ranking: {candidate.ineligibility_reason}"

    f = candidate.factors
    components = [
        f"disposability (+{config.w_disposability * f.test_disposability:.2f})",
        f"cooperative_support (+{config.w_cooperative_support * f.cooperative_shutdown_support:.2f})",
        f"reversibility (+{config.w_reversibility * f.reversibility:.2f})",
        f"state_loss (-{config.w_state_loss * f.estimated_state_loss:.2f})",
        f"criticality (-{config.w_criticality * f.application_criticality:.2f})",
    ]
    return f"Score {candidate.score:.2f} based on: {', '.join(components)}."


def rank_candidates(candidates: List[RecoveryCandidate],
                    config: ScoringConfig = DEFAULT_SCORING_CONFIG) -> List[RecoveryCandidate]:
    """
    Scores and ranks all candidates, placing eligible actions first in descending score order.
    """
    scored: List[RecoveryCandidate] = []
    for cand in candidates:
        if cand.is_eligible:
            cand.score = calculate_score(cand.factors, config)
            cand.ranking_rationale = generate_ranking_rationale(cand, config)
        else:
            cand.score = -1.0
            cand.ranking_rationale = f"Action rejected by policy: {cand.ineligibility_reason}"
        scored.append(cand)

    # Sort: eligible candidates first (descending score), then ineligible
    scored.sort(key=lambda c: (c.is_eligible, c.score), reverse=True)
    return scored

