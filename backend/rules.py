from __future__ import annotations

from backend.schemas import FeatureEvent, RuleDecision


def classify_with_rules(features: FeatureEvent) -> RuleDecision:
    if features.failed_auth_count >= 5:
        return RuleDecision(
            is_attack=True,
            predicted_attack_type="brute_force",
            severity="high",
            reason="Too many authentication failures from the same source in the recent window.",
        )

    if features.message_rate >= 25 or features.connect_rate >= 12:
        return RuleDecision(
            is_attack=True,
            predicted_attack_type="flood",
            severity="high",
            reason="Unusually high message/connect rate detected from one source.",
        )

    if features.topic_count >= 8:
        return RuleDecision(
            is_attack=True,
            predicted_attack_type="topic_scan",
            severity="medium",
            reason="Single source is touching many different topics in a short window.",
        )

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
