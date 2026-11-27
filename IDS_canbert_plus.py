"""
CANBERT+ IDS integration for YES, CARLA CAN.

Original CANBERT+ implementation:
https://github.com/OSUSecLab/CanBERTplus

Original authors:
Jun Yeon Won, Qadeer Ahmed and Zhiqiang Lin.

This module adapts the original CANBERT+ implementation
to receive and classify CAN messages from SocketCAN.
"""

import os
import sys
import json
from pathlib import Path
from time import monotonic as time_monotonic

import can
import torch

# CARLA ADAPTATION BEGIN
# from can_network import VCAN_CHANNEL, CAN_INTERFACE

VCAN_CHANNEL = "vcan0"
CAN_INTERFACE = "socketcan"
# CARLA ADAPTATION END


class CanBertPlusIntrusionDetection:

    def __init__(self):

        # CARLA ADAPTATION:
        # Counters based on the existing statistical IDS.

        self.intrusion_counter = {}
        self.regular_counter = 0

        self._last_line_count = 0
        self._last_alert = ""
        self._last_print_time = 0.0

        # CARLA ADAPTATION:
        # Buffer used to accumulate CAN message sequences.

        self.buffer = []

        self.model = None
        self.tokenizer = None
        self.sequence_length = None

        # CARLA ADAPTATION:
        # CPU inference for machines without CUDA.

        self.device = torch.device("cpu")

    def load(self, path=None):

        """
        Load the original CANBERT+ model and tokenizer.
        """

        # CARLA ADAPTATION BEGIN
        # Define paths relative to the defense directory.

        root = Path(__file__).resolve().parent

        repository = root / "CanBERTplus"

        pretrained = (
            root / "checkpoints" / "orig_ids.ckpt"
        )

        if path is None:
            path = root / "checkpoints" / "carla_ids.ckpt"

        checkpoint = Path(path).resolve()

        if not repository.is_dir():
            raise FileNotFoundError(repository)

        if not pretrained.is_file():
            raise FileNotFoundError(pretrained)

        if not checkpoint.is_file():
            raise FileNotFoundError(checkpoint)

        sys.path.insert(0, str(repository))

        current_dir = os.getcwd()

        # CARLA ADAPTATION END

        try:

            # CARLA ADAPTATION:
            # Preserve relative paths expected by the
            # original CANBERT+ configuration.

            os.chdir(repository)

            # ORIGINAL CANBERT+ COMPONENTS:
            # Imported directly from the authors' repository.
            # No neural architecture modifications.

            from config import TOKENIZER
            from can_finetune import CanIds

            self.tokenizer = TOKENIZER

            self.sequence_length = TOKENIZER.max_len

            self.model = CanIds(
                model_name=str(pretrained)
            )

            # CARLA ADAPTATION BEGIN
            # Load the fine-tuned model for CPU inference.

            state = torch.load(
                checkpoint,
                map_location=self.device,
                weights_only=True
            )

            self.model.load_state_dict(
                state["state_dict"]
            )

            self.model.to(self.device)

            self.model.eval()

            # CARLA ADAPTATION END

        finally:

            os.chdir(current_dir)

        print("[CANBERT+] Model loaded")

        print(f"Device: {self.device}")

        print(
            f"Sequence length: {self.sequence_length}"
        )

    def format_message(self, message):

        """
        CARLA ADAPTATION:

        Convert a python-can Message into the original
        CANBERT+ dataset representation.

        Original representation:
        CAN_ID DLC D1 D2 D3 D4 D5 D6 D7 D8
        """

        can_id = format(
            message.arbitration_id,
            "04X"
        )

        dlc = message.dlc

        data = [
            format(byte, "02x")
            for byte in message.data
        ]

        # Padding according to the original paper.

        data += ["-1"] * (8 - len(data))

        return f"{can_id} {dlc} " + " ".join(data)

    def predict(self, messages):

        """
        Classify a sequence using the original
        CANBERT+ neural network.
        """

        # CARLA ADAPTATION:
        # Convert SocketCAN messages into text sequences.

        formatted = [
            self.format_message(message)
            for message in messages
        ]

        # ORIGINAL CANBERT+ TOKENIZER:
        # The authors' encode_can method is preserved.

        encodings = self.tokenizer.encode_can(formatted)

        # CARLA ADAPTATION BEGIN
        # Prepare tensors for online inference.

        keys = [
            "canid_ids",
            "datalen_ids",
            "data0_ids",
            "data1_ids",
            "data2_ids",
            "data3_ids",
            "data4_ids",
            "data5_ids",
            "data6_ids",
            "data7_ids"
        ]

        inputs = [
            torch.tensor(
                encodings[key],
                dtype=torch.long,
                device=self.device
            ).unsqueeze(0)
            for key in keys
        ]

        # CARLA ADAPTATION END

        with torch.inference_mode():

            # ORIGINAL CANBERT+ MODEL:
            # Executes the original CanIds.forward().

            logits = self.model(*inputs)

            # CARLA ADAPTATION:
            # Validate the model output before classification.

            if logits.shape != (1, len(messages), 2):

                raise RuntimeError(
                    f"Unexpected output: {logits.shape}"
                )

            predictions = torch.argmax(
                logits,
                dim=-1
            )

        return predictions.squeeze(0).tolist()

    def run(self, message):

        """
        CARLA ADAPTATION:

        Receive a single CAN message and accumulate
        messages until a complete sequence is available.
        """

        if self.model is None:

            raise RuntimeError("Model not loaded")

        # Original CANBERT+ processes Classical CAN.

        if (
            message.is_fd
            or message.is_error_frame
            or message.is_remote_frame
            or message.dlc > 8
            or len(message.data) != message.dlc
        ):
            return

        self.buffer.append(message)

        if len(self.buffer) < self.sequence_length:

            return

        predictions = self.predict(self.buffer)

        alert = False

        for msg, prediction in zip(
            self.buffer,
            predictions
        ):

            id = format(msg.arbitration_id, "X")

            # Original CANBERT+ binary classification:
            # 0 = benign
            # 1 = malicious

            if prediction == 1:

                if id not in self.intrusion_counter:

                    self.intrusion_counter[id] = 1

                else:

                    self.intrusion_counter[id] += 1

                alert = True

            else:

                self.regular_counter += 1

        self.buffer.clear()

        self.print_results(alert=alert)

    def print_results(self, alert=False):

        """
        CARLA ADAPTATION:

        Terminal interface based on the existing
        IdTimeIntrusionDetection implementation.
        """

        RESET  = "\033[0m"
        RED    = "\033[91m"
        YELLOW = "\033[93m"
        CYAN   = "\033[96m"
        DIM    = "\033[2m"

        SEP = DIM + "\u2500" * 44 + RESET

        if alert:

            self._last_alert = (
                f"{RED}[ALERT] CANBERT+ intrusion detected"
                f"{RESET}"
            )

        is_alert = alert

        now = time_monotonic()

        if (
            not is_alert
            and (now - self._last_print_time) < 0.1
        ):
            return

        self._last_print_time = now

        lines = [SEP]

        if self._last_alert:

            lines.append(self._last_alert)

        lines.append(
            f"Regular messages : "
            f"{CYAN}{self.regular_counter}{RESET}"
        )

        total = sum(self.intrusion_counter.values())

        lines.append(
            f"Total intrusions : "
            f"{(RED if total else CYAN)}{total}{RESET}"
        )

        if self.intrusion_counter:

            lines.append(
                f"{YELLOW}Intrusion counts :{RESET}"
            )

            for json_line in json.dumps(
                self.intrusion_counter,
                indent=2
            ).splitlines():

                lines.append(f"  {json_line}")

        lines.append(SEP)

        # Overwrite the previous block in-place.

        if self._last_line_count > 0:

            sys.stdout.write(
                f"\033[{self._last_line_count}A"
            )

            for _ in range(self._last_line_count):

                sys.stdout.write("\033[2K\n")

            sys.stdout.write(
                f"\033[{self._last_line_count}A"
            )

        sys.stdout.write("\n".join(lines) + "\n")

        sys.stdout.flush()

        self._last_line_count = len(lines)


# CARLA ADAPTATION BEGIN
# Standalone execution, without modifying the original
# intrusion_detection_module.py.

def main():

    detector = CanBertPlusIntrusionDetection()

    detector.load()

    bus = can.Bus(
        channel=VCAN_CHANNEL,
        interface=CAN_INTERFACE
    )

    print(f"Monitoring {VCAN_CHANNEL}...")

    try:

        while True:

            message = bus.recv(timeout=1.0)

            if message is not None:

                detector.run(message)

    except KeyboardInterrupt:

        print("\nStopping CANBERT+ IDS...")

        print(
            f"Pending messages: {len(detector.buffer)}"
        )

    finally:

        bus.shutdown()


if __name__ == "__main__":

    main()

# CARLA ADAPTATION END
