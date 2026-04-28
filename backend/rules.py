from __future__ import annotations

import re

from backend.schemas import FeatureEvent, RuleDecision

# ── Whitelisted topic prefixes ────────────────────────────────────────────────
# Known factory / IoT device topics that send periodic telemetry.
# Traffic matching these prefixes is exempt from flood and topic-scan rules
# because legitimate devices (M5Stack vibration monitor, door sensor, etc.)
# can easily exceed rate thresholds with normal periodic publishing.
WHITELISTED_TOPIC_PREFIXES = (
    "/factory/",
)


def _is_whitelisted_topic(topic: str) -> bool:
    """Return True if the topic belongs to a known factory device."""
    return any(topic.startswith(prefix) for prefix in WHITELISTED_TOPIC_PREFIXES)


def classify_with_rules(
    features: FeatureEvent,
    topic: str = "/",
    action: str = "publish",
) -> RuleDecision:
    """
    Rule-based classifier.

    Parameters
    ----------
    features : FeatureEvent
        Aggregated traffic features for the source.
    topic : str
        The topic of the *current* event — used for whitelist checks.
    action : str
        The action of the *current* event ("connect", "publish", "auth_fail", etc.).
    """
    whitelisted = _is_whitelisted_topic(topic)

    # ── Brute Force: many auth failures from same IP (any client_id) ──────────
    # (never whitelisted — auth failures are always suspicious)
    if features.failed_auth_count >= 3 and action in ("connect", "auth_fail"):
        return RuleDecision(
            is_attack=True,
            predicted_attack_type="brute_force",
            severity="high",
            reason="Multiple authentication failures from the same source IP.",
        )

    # ── Flood: high message or connection rate from one client ─────────────────
    if not whitelisted and (features.message_rate >= 25 or features.connect_rate >= 12):
        return RuleDecision(
            is_attack=True,
            predicted_attack_type="flood",
            severity="high",
            reason="Unusually high message/connect rate detected from one source.",
        )

    # ── Topic Scan: single client touching many different topics ───────────────
    if not whitelisted and features.topic_count >= 6:
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
