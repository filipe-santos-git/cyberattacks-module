
# Cyberattacks Module for CAN Networks

An experimental framework for automotive cybersecurity research, focused on Controller Area Network (CAN) attacks, traffic analysis, dataset generation, and machine learning-based intrusion detection.

This project extends the YES, CARLA CAN simulation environment with additional attack modules, experimental datasets, and a Transformer-based Intrusion Detection System (IDS).

## Attack Modules

### CAN Traffic Sniffer

The sniffer captures CAN traffic and stores the collected frames in a CSV file.

The following information is recorded:

- Timestamp
- Arbitration ID
- Data Length Code (DLC)
- Payload
- Extended identifier flag

The sniffer provides the traffic capture infrastructure used by the Replay and Payload Corruption modules.

Captured traffic is stored in `traffic_logs/can_sniffer.csv`.

### Replay Attack

The Replay module implements an attack based on the reproduction of previously captured CAN messages.

Unlike a simple sequential replay, this implementation analyzes the temporal behavior of individual CAN identifiers by calculating their average transmission intervals.

Its main characteristics include:

- Automatic traffic capture.
- Message grouping by CAN identifier.
- Average transmission interval estimation.
- Independent temporal scheduling for each CAN identifier.
- Preservation of original payloads.
- Integration with the virtual attacker CAN interface.

The implementation enables controlled evaluation of replay detection mechanisms within the YES, CARLA CAN simulation environment.

### Fake Data Fabrication (I1) \u2013 Payload Corruption

Payload corruption is integrated into `attacks/replay.py`.

The attack preserves the original CAN identifier and DLC while modifying selected payload bits through a bitwise XOR operation.

The replay module supports two payload-corruption modes:

- Fixed XOR mask supplied by the user through `--mask`.
- Random XOR mask generated automatically when `--fake_data` is enabled without `--mask`.

The XOR operation allows precise control over which bits are modified:

- A binary word bit equal to `0` preserves the original bit.
- A binary word bit equal to `1` inverts the original bit.

Conceptual example:

```text
Original payload: 10110100
Binary word:      00000101
                  -------- XOR
Corrupted data:   10110001
```

When a fixed mask is provided, the same mask is used for the replayed CAN messages. When no mask is provided, a new random mask is generated according to the DLC of each message.

The payload length and CAN DLC are preserved after the XOR operation.

Payload Corruption was not included in the CANBERT+ supervised fine-tuning dataset.

## Defense Modules

### CANBERT+ Intrusion Detection System

CANBERT+ is a Transformer-based architecture designed for CAN network intrusion detection.

This project adapts the original CANBERT+ implementation to the YES, CARLA CAN simulation environment through custom datasets, model training, and a dedicated inference module.

The model processes sequences of 64 CAN frames using the following information:

- CAN identifiers.
- Data Length Codes.
- Individual payload bytes.
- Sequential positional information.

The model performs binary classification for individual CAN frames:

| Label | Classification |
|-------|----------------|
| 0 | Benign |
| 1 | Malicious |

The adapted IDS operates independently of the CARLA Python environment, allowing CPU-based inference through a dedicated Conda environment.

### Model Architecture

The original CANBERT+ architecture is preserved wherever possible.

| Parameter | Value |
|-----------|-------|
| Architecture | BERT-based Transformer |
| Hidden size | 768 |
| Transformer layers | 6 |
| Attention heads | 12 |
| Sequence length | 64 |
| Trainable parameters | Approximately 49 million |
| Output classes | 2 |

The architecture does not directly use message timestamps as model inputs.

### Model Training

The training process consists of two stages: benign traffic pre-training and supervised fine-tuning.

#### Stage 1 \u2013 Pre-training

The model was initially trained exclusively on benign CAN traffic collected from YES, CARLA CAN.

Custom vocabularies were generated from the collected traffic, representing CAN identifiers, DLCs, and payload bytes.

| Parameter | Value |
|-----------|-------|
| Dataset | carla_benign.csv |
| CAN frames | 23,221 |
| Unique CAN identifiers | 15 |
| Capture duration | Approximately 6 min 36 s |
| Sequence length | 64 |
| Epochs | 10 |
| Batch size | 32 |
| GPU | NVIDIA Tesla T4 |
| Output checkpoint | orig_ids.ckpt |

The pre-training stage establishes a representation of legitimate CAN communication patterns.

#### Stage 2 \u2013 Supervised Fine-tuning

The pre-trained model was subsequently fine-tuned using benign and malicious CAN traffic.

The attack scenarios included in the fine-tuning dataset were:

- Spoofing.
- Fuzzy.
- Replay.

The dataset was adjusted to reduce the predominance of spoofing messages while preserving the original order of CAN frames within each sequence.

All model parameters remained trainable during fine-tuning.

| Parameter | Value |
|-----------|-------|
| Dataset | carla_train.csv |
| CAN frames | 58,880 |
| Total sequences | 920 |
| Training sequences | 736 |
| Testing sequences | 184 |
| Training split | 80% |
| Testing split | 20% |
| Sequence length | 64 |
| Epochs | 10 |
| Batch size | 32 |
| Trainable parameters | Approximately 49 million |
| GPU | NVIDIA Tesla T4 |
| Output checkpoint | carla_ids.ckpt |

## Experimental Results

### Classification Performance

The following results were obtained from the internal test partition of the supervised fine-tuning dataset.

| Metric | Result |
|--------|-------:|
| Training Accuracy | 93.00% |
| Testing Accuracy | 92.26% |
| Precision | 82.36% |
| Recall | 98.33% |
| F1-score | 89.64% |
| False Positive Rate | 10.86% |
| False Negative Rate | 1.67% |

Precision and recall were interpreted using the corrected definitions of false positives and false negatives, due to an inversion identified in the original CANBERT+ metric counters.

### Confusion Matrix

Absolute confusion matrix:

| Actual / Predicted | Benign | Malicious |
|--------------------|-------:|----------:|
| Benign | 6,925 | 844 |
| Malicious | 67 | 3,940 |

Row-normalized confusion matrix:

| Actual / Predicted | Benign | Malicious |
|--------------------|-------:|----------:|
| Benign | 89.14% | 10.86% |
| Malicious | 1.67% | 98.33% |

The model correctly detected 98.33% of malicious CAN frames within the internal test dataset.

These results represent an initial experimental evaluation using partitions of the collected traffic, rather than an independent evaluation across different driving sessions.

### Training Accuracy Evolution

| Epoch | Accuracy |
|------:|---------:|
| 1 | 80.30% |
| 2 | 90.40% |
| 3 | 91.90% |
| 4 | 92.50% |
| 5 | 92.70% |
| 6 | 92.80% |
| 7 | 92.90% |
| 8 | 93.00% |
| 9 | 93.00% |
| 10 | 93.00% |

The training loss decreased from approximately 1.121 to 0.110 in the reported training logs.

### CPU Inference Performance

An isolated CPU inference experiment was performed using a synthetic sequence of 64 CAN frames.

| Metric | Result |
|--------|-------:|
| Processing device | CPU |
| Sequence length | 64 frames |
| Inference time | 35.1 ms |
| Estimated throughput | 1,825 frames/s |

These measurements represent an isolated inference operation and do not include continuous CAN reception, buffer accumulation, or simulation overhead.

## Datasets

The repository provides raw CAN traffic captures and processed datasets used during model development.

### Raw Datasets

Located in `datasets/raw/`.

| File | Description |
|------|-------------|
| can_sniffer.csv | Original CAN traffic capture |
| spoofing.log | Spoofing experiment capture |
| fuzzy.log | Fuzzy experiment capture |
| replay.log | Replay experiment capture |

The attack logs were collected using virtual CAN interfaces within the YES, CARLA CAN simulation environment.

The simulation infrastructure allows traffic labeling according to message origin:

| Direction | Classification | Label |
|-----------|----------------|-------|
| T | Benign | 0 |
| R | Malicious | 1 |

This labeling mechanism is specific to the virtual CAN infrastructure used in these experiments and is not a general property of the CAN protocol.

### Processed Datasets

Located in `datasets/processed/`.

| File | Description | CAN Frames |
|------|-------------|-----------:|
| carla_benign.csv | Benign pre-training dataset | 23,221 |
| carla_train.csv | Selected fine-tuning dataset | 58,880 |
| carla_labeled_full.csv | Complete labeled sequences | 160,064 |

The processed datasets contain CAN frame representations compatible with the CANBERT+ tokenizer.

Each frame representation contains:

- CAN identifier.
- DLC.
- Eight payload byte positions.

Unused payload positions are represented by padding values.

The supervised datasets additionally contain a binary classification label.

The complete labeled dataset is provided for additional experiments and alternative training configurations.

## Installation and Configuration

### Prerequisites

- Linux
- Git
- Conda
- Python
- CAN utilities
- YES, CARLA CAN simulation environment

### Simulation Environment

Install and configure YES, CARLA CAN according to its official repository:

https://github.com/luigiluz/yes-carla-can

The CARLA simulation environment and CANBERT+ inference environment should remain independent to avoid dependency conflicts.

Clone this repository:

```bash
git clone https://github.com/filipe-santos-git/cyberattacks-module.git
```

The attack and defense modules are designed to operate within the configured YES, CARLA CAN project structure.

### CANBERT+ Python Environment

Create a dedicated Conda environment:

```bash
conda create -n canbert python=3.12
conda activate canbert
```

Install PyTorch with CPU support:

```bash
python -m pip install torch \
    --index-url https://download.pytorch.org/whl/cpu
```

Install the remaining dependencies:

```bash
python -m pip install \
    lightning==2.3.2 \
    transformers==4.37.2 \
    setuptools==80.10.2 \
    python-can \
    numpy \
    pandas \
    psutil \
    tqdm
```

Verify the installation:

```bash
python -c "import torch, lightning, transformers, can; print('PyTorch:', torch.__version__); print('Lightning:', lightning.__version__); print('Transformers:', transformers.__version__); print('CUDA:', torch.cuda.is_available())"
```

For CPU-based inference, `CUDA: False` is expected.

### Downloading the Trained Model

The trained CANBERT+ model is available through GitHub Releases.

[Download CANBERT+ Experimental Release v0.1.0](https://github.com/filipe-santos-git/cyberattacks-module/releases/tag/v0.1.0)

The release archive is named:

```text
canbert_plus_carla.zip
```

It includes:

- CANBERT+ source code.
- Adapted IDS module.
- Pre-trained model checkpoint.
- Fine-tuned model checkpoint.
- Custom CAN identifier vocabulary.
- Custom DLC vocabulary.
- Custom payload vocabulary.

Extract the archive into the root directory of the configured YES, CARLA CAN project.

```bash
unzip canbert_plus_carla.zip -d /path/to/yes-carla-can/
```

Replace `/path/to/yes-carla-can/` with the actual installation path.


The vocabulary files must remain consistent with the trained checkpoints. Regenerating the vocabularies may result in incompatibility with the existing model parameters.

## Running the Simulation

From the YES, CARLA CAN root directory:

```bash
conda activate n4s_env

./1_up_environment.sh
```

The simulator provides the virtual CAN infrastructure used by the experimental modules.

## Running the Attacks

Run the attack commands from the root directory of the configured YES, CARLA CAN project while the simulation environment is active.

### Replay Attack

The replay attack first captures legitimate CAN traffic for the duration specified with `--duration`. It then retransmits the captured messages while preserving the average transmission interval observed for each CAN ID.

Basic replay attack with a 3-second sniffing period:

```bash
PYTHONPATH=. python3 attacks/replay.py --duration 3
```

Example with a 10-second sniffing period:

```bash
PYTHONPATH=. python3 attacks/replay.py --duration 10
```

Stop the attack with `Ctrl+C`.

### Replay Attack with Fixed Payload Corruption

Payload corruption can be enabled directly in the replay attack with `--fake_data`.

To use a fixed XOR mask:

```bash
PYTHONPATH=. python3 attacks/replay.py --duration 3 --fake_data --mask 00000001
```

Another example using an 8-bit mask:

```bash
PYTHONPATH=. python3 attacks/replay.py --duration 3 --fake_data --mask 11111111
```

The value supplied to `--mask` must be a binary word containing only `0` and `1`.

The fixed mask is applied through XOR while preserving the original CAN ID and DLC.

### Replay Attack with Random Payload Corruption

If `--fake_data` is enabled without `--mask`, the replay module generates a random XOR mask for each transmitted CAN message:

```bash
PYTHONPATH=. python3 attacks/replay.py --duration 3 --fake_data
```

The random mask size is automatically limited according to the DLC of the current CAN message.

Therefore, `attacks/replay.py` supports three operating modes:

```text
Normal Replay
Replay + Fixed XOR Payload Corruption
Replay + Random XOR Payload Corruption
```

### Spoofing Attack

Feature spoofing is provided by the original YES, CARLA CAN `cyberattacks_module.py`.

For example, the hand-brake spoofing attack can be executed with:

```bash
conda run --no-capture-output -n n4s_env python3 cyberattacks_module.py --feature hand_brake --period 0.001
```

The `--period` argument defines the interval between injected CAN messages.

Other supported spoofing targets can be listed with:

```bash
conda run --no-capture-output -n n4s_env python3 cyberattacks_module.py --help
```

Stop the attack with `Ctrl+C`.

### Fuzzy Attack

The fuzzy attack is also provided by the original YES, CARLA CAN attack module.

Run it with:

```bash
conda run --no-capture-output -n n4s_env python3 cyberattacks_module.py --feature fuzzy --period 0.05
```

The `--period` argument controls the interval between generated CAN messages.

Stop the attack with `Ctrl+C`.

### Attack Execution Summary

| Attack | Command / Mode | Origin |
|---|---|---|
| Replay | `PYTHONPATH=. python3 attacks/replay.py --duration <seconds>` | This project |
| Replay + fixed payload corruption | `--fake_data --mask <binary_mask>` | This project |
| Replay + random payload corruption | `--fake_data` | This project |
| Feature spoofing | `--feature hand_brake --period 0.001` | YES, CARLA CAN |
| Fuzzy | `--feature fuzzy --period 0.05` | YES, CARLA CAN |

## Running CANBERT+

In a separate terminal, navigate to the YES, CARLA CAN root directory and activate the CANBERT+ environment.

```bash
conda activate canbert

PYTHONPATH=. python3 defense/IDS_canbert_plus.py
```

Alternatively, execute the IDS directly through Conda:

```bash
PYTHONPATH=. conda run --no-capture-output \
    -n canbert \
    python3 defense/IDS_canbert_plus.py
```

The IDS listens to the virtual CAN interface, accumulates sequences of 64 messages, and performs binary classification.

The inference module maintains counters for legitimate messages and detected intrusions.

### Validating Model Loading

The following command can be used to verify the model installation without starting the simulator:

```bash
PYTHONPATH=. python - <<'PY'
from defense.IDS_canbert_plus import CanBertPlusIntrusionDetection

ids = CanBertPlusIntrusionDetection()
ids.load()

print("Model loaded successfully!")
print("Device:", ids.device)
print("Sequence length:", ids.sequence_length)
PY
```

Expected output:

```text
Model loaded successfully!
Device: cpu
Sequence length: 64
```

### Attack Module Integration

The attack modules are located in the `attacks/` directory.

They are designed for controlled experimentation within YES, CARLA CAN and depend on its traffic capture and virtual CAN communication infrastructure.

The custom Replay module supports normal replay, fixed XOR payload corruption, and random XOR payload corruption.

The original YES, CARLA CAN simulation environment provides the Spoofing and Fuzzy attack scenarios through `cyberattacks_module.py`.

## Research Objectives

This project investigates several aspects of automotive cybersecurity:

- CAN traffic characterization.
- Automotive attack modeling.
- Replay and payload manipulation experiments.
- Dataset collection and generation.
- Transformer-based intrusion detection.
- Machine learning model adaptation.
- Detection of previously unseen attack patterns.
- Computational feasibility of intrusion detection.
- Potential deployment in embedded automotive systems.

All experiments are intended exclusively for isolated and authorized simulation environments.

## References and Acknowledgments

### YES, CARLA CAN

Original simulation environment and virtual CAN communication infrastructure.

https://github.com/luigiluz/yes-carla-can

### CANBERT+

Original Transformer-based CAN intrusion detection architecture developed by OSUSecLab.

https://github.com/OSUSecLab/CanBERTplus

### CAN Security Taxonomy

Serag et al. *SoK: Kicking CAN Down the Road: Systematizing CAN Security Knowledge*, 2025.

This project builds upon these works while contributing additional attack modules, simulation-specific datasets, model training, and intrusion detection integration.

The original CANBERT+ architecture and YES, CARLA CAN infrastructure are credited to their respective authors.
