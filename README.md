# RustGen - Generación de firmas de malware mediante algoritmos genéticos

## Requisitos previos
- Rust (cargo)
- Python 3.10+
- Bibliotecas Python: pandas, numpy, tqdm

## Configuración del entorno
1. Clonar el repositorio:
   ```
   git clone https://github.com/tu-usuario/rustgen.git
   cd rustgen
   ```

2. Descargar datos de muestra:
   ```
   mkdir -p data/ember2024
   wget -O data/ember2024/sample.jsonl https://github.com/futurecomputing4ai/ember2024/raw/main/sample.jsonl
   ```

3. Preprocesar los datos:
   ```
   python scripts/preprocess_ember.py
   ```

4. Compilar el proyecto:
   ```
   cargo build --release
   ```

## Ejecución
Para ejecutar con los datos completos:
```
cargo run --release
```

Para usar un conjunto reducido de datos (útil para pruebas):
```
head -n 100 data/processed/malware_bytes.txt > data/processed/malware_small.txt
head -n 100 data/processed/benign_bytes.txt > data/processed/benign_small.txt
MALWARE_PATH=data/processed/malware_small.txt BENIGN_PATH=data/processed/benign_small.txt cargo run --release
```

## Estructura de archivos
- `src/main.rs`: Código principal del algoritmo genético
- `scripts/preprocess_ember.py`: Preprocesamiento de datos EMBER
- `data/ember2024/`: Datos EMBER originales (formato JSONL)
- `data/processed/`: Datos preprocesados usados por el algoritmo
- `best_signature.txt`: Mejor firma encontrada (resultado)
- `fitness_history.png`: Gráfico de convergencia (resultado)

## Notas importantes
- Asegúrese de ejecutar el script de preprocesamiento antes de ejecutar el programa principal.
- Para conjuntos de datos grandes, el proceso puede tardar varios minutos.

