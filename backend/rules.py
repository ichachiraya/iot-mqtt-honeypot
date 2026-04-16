from __future__ import annotations

from backend.schemas import FeatureEvent, RuleDecision


def classify_with_rules(features: FeatureEvent) -> RuleDecision:
    # ── Brute Force: many auth failures from same IP (any client_id) ──────────
    if features.failed_auth_count >= 3:
        return RuleDecision(
            is_attack=True,
            predicted_attack_type="brute_force",
            severity="high",
            reason="Multiple authentication failures from the same source IP.",
        )

    # ── Flood: high message or connection rate from one client ─────────────────
    if features.message_rate >= 25 or features.connect_rate >= 12:
        return RuleDecision(
            is_attack=True,
            predicted_attack_type="flood",
            severity="high",
            reason="Unusually high message/connect rate detected from one source.",
        )

    # ── Topic Scan: single client touching many different topics ───────────────
    if features.topic_count >= 6:
        return RuleDecision(
            is_attack=True,
            predicted_attack_type="topic_scan",
            severity="medium",
            reason="Single source is touching many different topics in a short window.",
        )

    # ── Oversized Payload ──────────────────────────────────────────────────────
    if features.avg_payload_size >= 900:
        return RuleDecision(
            is_attack=True,
            predicted_attack_type="oversized_payload",
            severity="medium",
            reason="Average payload size is suspiciously large in the recent window.",
        )

    return RuleDecision(
        is_attack=False,
        predicted_attack_type="normal",
        severity="low",
        reason="Traffic is within the expected range.",
    )
