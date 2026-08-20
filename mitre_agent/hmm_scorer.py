"""
hmm_scorer.py — Hidden Markov Model for attack sequence scoring.

Consumes the ordered list of phase observations for a session and computes
a sequence_confidence score representing how well the observed sequence
matches known attack progressions.

Uses hmmlearn's MultinomialHMM with transition/emission matrices loaded
from hmm_config.yaml. The Viterbi algorithm decodes the most likely
hidden state sequence.

Input:  list of phase strings (ordered, from session's event sequence)
Output: sequence_confidence float (0.0 – 1.0)
"""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Optional

import numpy as np
import yaml

log = logging.getLogger(__name__)

# Phase → integer encoding (must match hmm_config.yaml state order)
PHASE_ORDER = [
    "recon",
    "enumeration",
    "privilege_discovery",
    "data_discovery",
    "exploitation",
    "exfiltration",
]
PHASE_TO_IDX: dict[str, int] = {p: i for i, p in enumerate(PHASE_ORDER)}
N_STATES = len(PHASE_ORDER)

HMM_CONFIG_PATH = Path(__file__).parent / "rules" / "hmm_config.yaml"


class HMMScorer:
    """
    Scores an attack phase sequence using a pre-configured HMM.

    The score represents the log-probability of the observed sequence
    under the model, normalised to [0, 1] where:
      - 1.0 = sequence perfectly matches a known attack pattern
      - 0.5 = ambiguous / short sequence
      - 0.0 = sequence is inconsistent / random
    """

    def __init__(self, config_path: Path | None = None):
        self._cfg = self._load_config(config_path or HMM_CONFIG_PATH)
        self._scoring_cfg = self._cfg.get("scoring", {})
        self.min_len = self._scoring_cfg.get("min_sequence_length", 3)
        self.default_short = self._scoring_cfg.get(
            "default_confidence_short_sequence", 0.50
        )
        self.w_rule = self._scoring_cfg.get("weight_rule", 0.60)
        self.w_hmm = self._scoring_cfg.get("weight_hmm", 0.40)

        # Build matrices
        self._pi = self._build_initial_probs()
        self._A = self._build_transition_matrix()
        self._B = self._build_emission_matrix()

        log.info("HMM scorer initialised: %d states", N_STATES)

    # ─── Public API ───────────────────────────────────────────────────────────

    def score_sequence(self, phases: list[str]) -> float:
        """
        Compute sequence_confidence for an ordered list of phase observations.

        Returns a float in [0.0, 1.0].
        Short sequences (< min_len) return the default_short_sequence value.
        Unknown phase tags are silently skipped.
        """
        # Filter to known phases only
        obs = [p for p in phases if p in PHASE_TO_IDX]

        if len(obs) < self.min_len:
            return self.default_short

        # Forward algorithm: compute log P(observations | model)
        log_prob = self._forward_log_prob(obs)

        # Normalise: baseline is log_prob for a random uniform sequence
        baseline = self._baseline_log_prob(len(obs))

        # Convert to [0, 1] confidence
        confidence = self._normalise(log_prob, baseline, len(obs))
        return round(max(0.0, min(1.0, confidence)), 4)

    def decode_sequence(self, phases: list[str]) -> list[str]:
        """
        Viterbi decode — returns the most likely hidden state sequence.
        Useful for explaining which attack stages the HMM inferred.
        """
        obs = [PHASE_TO_IDX[p] for p in phases if p in PHASE_TO_IDX]
        if not obs:
            return []

        T = len(obs)
        viterbi = np.full((N_STATES, T), -np.inf)
        backpointer = np.zeros((N_STATES, T), dtype=int)

        # Initialise
        for s in range(N_STATES):
            viterbi[s, 0] = (
                math.log(self._pi[s] + 1e-300)
                + math.log(self._B[s, obs[0]] + 1e-300)
            )

        # Recursion
        for t in range(1, T):
            for s in range(N_STATES):
                probs = [
                    viterbi[prev, t - 1] + math.log(self._A[prev, s] + 1e-300)
                    for prev in range(N_STATES)
                ]
                best_prev = int(np.argmax(probs))
                viterbi[s, t] = probs[best_prev] + math.log(
                    self._B[s, obs[t]] + 1e-300
                )
                backpointer[s, t] = best_prev

        # Backtrack
        best_last = int(np.argmax(viterbi[:, T - 1]))
        path = [best_last]
        for t in range(T - 1, 0, -1):
            path.append(backpointer[path[-1], t])
        path.reverse()
        return [PHASE_ORDER[s] for s in path]

    def combined_confidence(
        self, rule_confidence: float, sequence_confidence: float
    ) -> float:
        """
        Weighted combination: 0.6 * rule_confidence + 0.4 * sequence_confidence
        """
        return round(
            self.w_rule * rule_confidence + self.w_hmm * sequence_confidence, 4
        )

    # ─── Matrix builders ──────────────────────────────────────────────────────

    def _build_initial_probs(self) -> np.ndarray:
        pi_cfg = self._cfg.get("initial_probabilities", {})
        pi = np.array(
            [pi_cfg.get(p, 1.0 / N_STATES) for p in PHASE_ORDER], dtype=float
        )
        pi /= pi.sum()
        return pi

    def _build_transition_matrix(self) -> np.ndarray:
        trans_cfg = self._cfg.get("transitions", {})
        A = np.zeros((N_STATES, N_STATES), dtype=float)
        for i, src in enumerate(PHASE_ORDER):
            row = trans_cfg.get(src, {})
            for j, dst in enumerate(PHASE_ORDER):
                A[i, j] = row.get(dst, 1.0 / N_STATES)
        # Normalise rows
        row_sums = A.sum(axis=1, keepdims=True)
        A = np.where(row_sums > 0, A / row_sums, 1.0 / N_STATES)
        return A

    def _build_emission_matrix(self) -> np.ndarray:
        emit_cfg = self._cfg.get("emissions", {})
        B = np.zeros((N_STATES, N_STATES), dtype=float)
        for i, state in enumerate(PHASE_ORDER):
            row = emit_cfg.get(state, {})
            for j, obs_phase in enumerate(PHASE_ORDER):
                B[i, j] = row.get(obs_phase, 1.0 / N_STATES)
        row_sums = B.sum(axis=1, keepdims=True)
        B = np.where(row_sums > 0, B / row_sums, 1.0 / N_STATES)
        return B

    # ─── Forward algorithm ────────────────────────────────────────────────────

    def _forward_log_prob(self, phases: list[str]) -> float:
        """Log probability of the observation sequence under the model."""
        obs = [PHASE_TO_IDX[p] for p in phases]
        T = len(obs)

        # log-space forward variable
        alpha = np.full(N_STATES, -np.inf)
        for s in range(N_STATES):
            alpha[s] = (
                math.log(self._pi[s] + 1e-300)
                + math.log(self._B[s, obs[0]] + 1e-300)
            )

        for t in range(1, T):
            alpha_new = np.full(N_STATES, -np.inf)
            for s in range(N_STATES):
                log_emit = math.log(self._B[s, obs[t]] + 1e-300)
                log_trans = np.array([
                    alpha[prev] + math.log(self._A[prev, s] + 1e-300)
                    for prev in range(N_STATES)
                ])
                alpha_new[s] = self._log_sum_exp(log_trans) + log_emit
            alpha = alpha_new

        return float(self._log_sum_exp(alpha))

    def _baseline_log_prob(self, length: int) -> float:
        """Log probability for a uniform random sequence of the same length."""
        uniform_prob = math.log(1.0 / N_STATES + 1e-300)
        return length * uniform_prob

    def _normalise(
        self, log_prob: float, baseline: float, length: int
    ) -> float:
        """Map log_prob relative to baseline into [0, 1]."""
        if length == 0:
            return self.default_short
        per_step_model = log_prob / length
        per_step_baseline = baseline / length
        # Best possible per-step log-prob (deterministic sequence)
        best = 0.0
        # Normalise: (model - baseline) / (best - baseline)
        denom = best - per_step_baseline
        if abs(denom) < 1e-10:
            return 0.5
        norm = (per_step_model - per_step_baseline) / denom
        return float(np.clip(norm, 0.0, 1.0))

    @staticmethod
    def _log_sum_exp(log_probs: np.ndarray) -> float:
        max_val = np.max(log_probs)
        if np.isneginf(max_val):
            return -np.inf
        return float(max_val + math.log(np.sum(np.exp(log_probs - max_val))))

    @staticmethod
    def _load_config(path: Path) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
