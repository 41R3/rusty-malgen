# RustGen - Malware Signature Generation using Genetic Algorithms

**RustGen** is an experimental project that evolves malware signatures using genetic algorithms. It aims to generate effective byte sequence signatures by optimizing for high malware detection rates while minimizing false positives on benign files.

## Key Features
- Genetic algorithm implementation in Rust for performance
- Uses EMBER2024 datasets (malware/benign) for training and evaluation
- Parallel fitness evaluation with Rayon
- Generates human-readable byte sequence signatures
- Convergence visualization of the genetic algorithm

## Prerequisites
- Rust (cargo)
- Python 3.10+
- Python libraries: pandas, numpy, tqdm

## Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/tu-usuario/rustgen.git
   cd rustgen
   ```

2. Download sample data:
   ```bash
   mkdir -p data/ember2024
   wget -O data/ember2024/sample.jsonl https://github.com/FutureComputing4AI/EMBER2024/raw/main/sample.jsonl
   ```

3. Preprocess data:
   ```bash
   python scripts/preprocess_ember.py
   ```

4. Compile the project:
   ```bash
   cargo build --release
   ```

## Execution
To run with full datasets:
```bash
cargo run --release
```

To use a reduced dataset (recommended for testing):
```bash
head -n 100 data/processed/malware_bytes.txt > data/processed/malware_small.txt
head -n 100 data/processed/benign_bytes.txt > data/processed/benign_small.txt
MALWARE_PATH=data/processed/malware_small.txt BENIGN_PATH=data/processed/benign_small.txt cargo run --release
```

## File Structure
- `src/main.rs`: Core genetic algorithm implementation
- `scripts/preprocess_ember.py`: EMBER data preprocessing
- `data/ember2024/`: Original EMBER datasets (JSONL format)
- `data/processed/`: Preprocessed byte sequences
- `best_signature.txt`: Generated signature (output)
- `fitness_history.png`: Convergence graph (output)

## Dataset Information
This project uses the EMBER2024 dataset from:  
https://github.com/FutureComputing4AI/EMBER2024/tree/main

We specifically utilize:
- ELF Train Dataset
- ELF Test Dataset
- Challenge Dataset

**Note:** Due to hardware limitations during development, experiments were conducted using reduced subsets of the full EMBER2024 dataset. For production use, consider training on the complete dataset.

## Implementation Notes

### Genetic Algorithms for Malware Detection
**Objective:** Evolve effective malware signatures through natural selection

**Key Libraries:**
- `rand`: Signature mutation and crossover
- `rayon`: Parallel fitness evaluation
- `plotters`: Convergence visualization

### Algorithm Characteristics
- **Chromosome Representation:** Byte sequences (hex format)
- **Fitness Function:** Maximize (TPR - FPR) where:
  - TPR = True Positive Rate (malware detection)
  - FPR = False Positive Rate (benign misclassification)
- **Selection:** Tournament selection
- **Crossover:** Single-point crossover
- **Mutation:** Byte-level random mutations

### Important Considerations
- Always run the preprocessing script before execution
- Full dataset processing requires significant RAM (16GB+ recommended)
- Training time scales with:
  - Population size
  - Byte sequence length
  - Dataset size

## Example Output
```
Best signature: 7F454C46010101??00??00??00??00??000200
Fitness: 0.92
Detection rate: 95.2%
False positive rate: 3.2%
```

