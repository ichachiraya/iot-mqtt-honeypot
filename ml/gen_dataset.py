from __future__ import annotations

import random
from pathlib import Path

import pandas as pd

OUTPUT_PATH = Path(__file__).resolve().parent / "dataset.csv"


def noisy(value: int, noise: int) -> int:
    """Add random noise to a value, simulating real-world measurement variance."""
    return max(0, value + random.randint(-noise, noise))


def generate_row(label: str) -> dict:
    """
    Generate a single synthetic event row for the given attack label.

    Feature ranges are intentionally overlapping to create a realistic,
    non-trivial classification problem. For example:
    - flood and topic_scan share similar message_rate ranges
    - normal and low-intensity attacks overlap in connect_rate
    - A 5-10% chance of a "noisy sample" further blurs boundaries
    """
    # Random chance (~8%) to generate an ambiguous/edge-case sample
    is_noisy = random.random() < 0.08

    if label == "normal":
        row = {
            "connect_rate": random.randint(0, 4),
            "message_rate": random.randint(1, 10),
            "topic_count": random.randint(1, 4),
            "avg_payload_size": random.randint(20, 300),
            "failed_auth_count": random.randint(0, 1),
        }
        if is_noisy:
            row["message_rate"] = random.randint(8, 18)  # Overlaps with flood/topic_scan
            row["connect_rate"] = random.randint(3, 7)

    elif label == "flood":
        row = {
            "connect_rate": random.randint(5, 20),
            "message_rate": random.randint(15, 65),
            "topic_count": random.randint(1, 5),
            "avg_payload_size": random.randint(30, 400),
            "failed_auth_count": random.randint(0, 3),
        }
        if is_noisy:
            row["message_rate"] = random.randint(8, 16)  # Overlaps with normal
            row["connect_rate"] = random.randint(3, 6)

    elif label == "brute_force":
        row = {
            "connect_rate": random.randint(2, 10),
            "message_rate": random.randint(0, 6),
            "topic_count": random.randint(1, 3),
            "avg_payload_size": random.randint(10, 150),
            "failed_auth_count": random.randint(4, 18),
        }
        if is_noisy:
            row["failed_auth_count"] = random.randint(2, 5)  # Overlaps with normal/flood
            row["avg_payload_size"] = random.randint(100, 300)

    elif label == "topic_scan":
        row = {
            "connect_rate": random.randint(1, 6),
            "message_rate": random.randint(8, 22),
            "topic_count": random.randint(7, 22),
            "avg_payload_size": random.randint(15, 200),
            "failed_auth_count": random.randint(0, 3),
        }
        if is_noisy:
            row["topic_count"] = random.randint(3, 8)  # Overlaps with normal
            row["message_rate"] = random.randint(5, 10)

    elif label == "oversized_payload":
        row = {
            "connect_rate": random.randint(1, 5),
            "message_rate": random.randint(1, 15),
            "topic_count": random.randint(1, 5),
            # Lowered ceiling and raised normal ceiling to create some overlap
            "avg_payload_size": random.randint(400, 2500),
            "failed_auth_count": random.randint(0, 2),
        }
        if is_noisy:
            row["avg_payload_size"] = random.randint(250, 500)  # Overlaps with normal/flood

    else:
        raise ValueError(f"Unknown label: {label}")

    row["attack_type"] = label
    return row


def main() -> None:
    random.seed(42)
    labels = ["normal", "flood", "brute_force", "topic_scan", "oversized_payload"]
    rows: list[dict] = []

    # Use 400 samples per class (2000 total) for a more robust dataset
    for label in labels:
        for _ in range(400):
            rows.append(generate_row(label))

    random.shuffle(rows)
    frame = pd.DataFrame(rows)
    frame.to_csv(OUTPUT_PATH, index=False)
    print(f"Saved {len(frame)} rows to {OUTPUT_PATH}")
    print(frame["attack_type"].value_counts())


if __name__ == "__main__":
    main()
