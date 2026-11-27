
import argparse
import random
import pandas as pd

from pathlib import Path
from sniffer import capture_traffic


LOG_DIR = Path("traffic_logs")
LOG_FILE = LOG_DIR / "can_sniffer.csv"
OUTPUT_FILE = LOG_DIR / "payload_corruption.csv"

CAPTURE_DURATION = 10


def payload_corruption(ID=None, binary_word=None):

    df = pd.read_csv(LOG_FILE, dtype={"data": str})

    candidates = df[df["dlc"].between(1, 8)]

    if binary_word is not None:

        if not binary_word or set(binary_word) - {"0", "1"}:
            raise ValueError("Invalid binary word.")

        if int(binary_word, 2) == 0:
            raise ValueError("Binary word must not be zero.")

        candidates = candidates[
            candidates["dlc"] * 8 == len(binary_word)
        ]

    if candidates.empty:
        raise ValueError("No compatible messages found.")

    if ID is None:
        ID = random.choice(
            candidates["arbitration_id"].unique().tolist()
        )

    messages = candidates[
        candidates["arbitration_id"] == ID
    ]

    if messages.empty:
        raise ValueError("No compatible messages for this ID.")

    result = df.copy()
    result["original_data"] = result["data"]
    result["binary_word"] = ""
    result["label"] = 0

    print(f"Selected CAN ID: {ID:#05x}")

    for index, message in messages.iterrows():

        payload = bytes.fromhex(message["data"])
        size = len(payload) * 8

        if size != int(message["dlc"]) * 8:
            raise ValueError("Payload and DLC mismatch.")

        word = binary_word

        if word is None:
            word = format(
                random.randint(1, (1 << size) - 1),
                f"0{size}b"
            )

        original = int.from_bytes(payload, "big")

        corrupted = original ^ int(word, 2)

        corrupted_payload = corrupted.to_bytes(
            len(payload), "big"
        )

        result.at[index, "data"] = corrupted_payload.hex()
        result.at[index, "binary_word"] = word
        result.at[index, "label"] = 1

    return result


def main():

    parser = argparse.ArgumentParser(
        description="CAN Payload Corruption Experiment"
    )

    parser.add_argument(
        "--id",
        type=lambda value: int(value, 16),
        default=None,
        help="Target CAN ID in hexadecimal."
    )

    parser.add_argument(
        "--binary_word",
        type=str,
        default=None,
        help="Binary word used in the XOR operation."
    )

    args = parser.parse_args()

    try:

        print("Capturing CAN traffic...")

        capture_traffic(duration=CAPTURE_DURATION)

        print("Starting payload corruption...")

        result = payload_corruption(
            ID=args.id,
            binary_word=args.binary_word
        )

        result.to_csv(OUTPUT_FILE, index=False)

        print("Payload corruption finished.")
        print("Corrupted messages:", result["label"].sum())
        print("Output file:", OUTPUT_FILE)

    except KeyboardInterrupt:

        print("\nExperiment interrupted.")

    except ValueError as error:

        print(f"Error: {error}")


if __name__ == "__main__":
    main()

