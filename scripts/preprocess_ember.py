import numpy as np
import json
import os
from tqdm import tqdm

def extract_features(record, max_length=256):
    features = []

    # ===== 1. Características GENERALES =====
    general = record.get("general", {})
    features.append(general.get("size", 0))
    features.append(general.get("entropy", 0))
    features.append(general.get("is_pe", 0))  # 0 para ELF, 1 para PE

    # ===== 2. Información de secciones/segmentos =====
    sections = record.get("section", {}).get("sections", [])

    # Características de secciones (hasta 3 secciones)
    for section in sections[:3]:
        features.append(section.get("entropy", 0))
        features.append(section.get("vsize", 0))
        features.append(section.get("size", 0))
    # Rellenar con ceros si hay menos de 3 secciones
    features.extend([0] * (9 - 3*len(sections[:3])))

    # ===== 3. Histograma de bytes =====
    histogram = record.get("histogram", [])
    if histogram:
        features.extend([
            np.mean(histogram),
            np.max(histogram),
            np.percentile(histogram, 90),
            np.percentile(histogram, 75),
            len(histogram)  # Tamaño del histograma
        ])
    else:
        features.extend([0] * 5)

    # ===== 4. Byteentropy =====
    byteentropy = record.get("byteentropy", [])
    if byteentropy:
        features.extend([
            np.mean(byteentropy),
            np.max(byteentropy),
            np.percentile(byteentropy, 90)
        ])
    else:
        features.extend([0] * 3)

    # ===== 5. Strings =====
    strings = record.get("strings", {})
    features.append(strings.get("numstrings", 0))
    features.append(strings.get("avlength", 0))
    features.append(strings.get("entropy", 0))

    # Top 5 strings más comunes
    string_counts = strings.get("string_counts", {})
    top_strings = sorted(string_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    for s, count in top_strings:
        features.append(count)
    if len(top_strings) < 5:
        features.extend([0] * (5 - len(top_strings)))

    # ===== 6. Características específicas de PE =====
    if general.get("is_pe", 0) == 1:  # Es PE
        header = record.get("header", {})
        optional = header.get("optional", {})

        # Características del header PE
        features.append(optional.get("sizeof_code", 0))
        features.append(optional.get("sizeof_initialized_data", 0))
        features.append(len(record.get("imports", {})))  # Número de DLLs importadas

        # Información de datadirectories
        datadirs = record.get("datadirectories", [])
        features.append(len([d for d in datadirs if d.get("size", 0) > 0]))

        # Rich header
        richheader = record.get("richheader", [])
        features.append(len(richheader))

        # Authenticode
        auth = record.get("authenticode", {})
        features.append(auth.get("num_certs", 0))
    else:  # Es ELF
        # Características específicas de ELF
        features.append(len(record.get("behavior", [])))
        features.append(len(record.get("file_property", [])))
        features.append(len(record.get("packer", [])))
        features.extend([0] * 3)  # Rellenar características PE faltantes

    # ===== 7. Información de familia =====
    features.append(record.get("family_confidence", 0))

    # ===== 8. Características adicionales =====
    features.append(len(record.get("exports", [])))
    features.append(len(record.get("group", [])))

    # ===== Convertir a bytes [0-255] y asegurar longitud =====
    byte_features = []
    for value in features:
        if isinstance(value, (int, float)):
            # Escalar y asegurar que esté en [0, 255]
            scaled = min(255, max(0, int(value)))
        else:
            scaled = 0
        byte_features.append(scaled)

    # Rellenar o truncar a la longitud máxima
    if len(byte_features) < max_length:
        byte_features.extend([0] * (max_length - len(byte_features)))
    else:
        byte_features = byte_features[:max_length]

    return byte_features

def process_ember_dataset():
    malware_samples = []
    benign_samples = []
    input_dir = "data/ember2024"
    output_dir = "data/processed"

    # Crear directorios de entrada y salida si no existen
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    # Verificar si hay archivos para procesar
    jsonl_files = [f for f in os.listdir(input_dir) if f.endswith('.jsonl')]
    
    if not jsonl_files:
        print(f"ADVERTENCIA: No se encontraron archivos .jsonl en {input_dir}")
        print("Descargue primero los archivos de muestra. Ejemplo:")
        print("  mkdir -p data/ember2024")
        print("  wget -O data/ember2024/sample.jsonl https://github.com/futurecomputing4ai/ember2024/raw/main/sample.jsonl")
        return

    # Procesar cada archivo
    for filename in jsonl_files:
        filepath = os.path.join(input_dir, filename)
        with open(filepath, 'r') as f:
            lines = f.readlines()
            for line in tqdm(lines, desc=f"Processing {filename}"):
                try:
                    record = json.loads(line)
                    # Extraer características
                    features = extract_features(record)
                    # Convertir a representación hexadecimal
                    hex_features = " ".join(f"{b:02X}" for b in features)

                    # Separar por etiqueta
                    label = record.get("label", 0)
                    if label == 1:  # Malware
                        malware_samples.append(hex_features)
                    else:  # Benigno
                        benign_samples.append(hex_features)
                except json.JSONDecodeError:
                    print(f"Error decodificando JSON en {filename}: {line}")
                    continue

    # Guardar muestras en archivos
    malware_path = os.path.join(output_dir, "malware_bytes.txt")
    benign_path = os.path.join(output_dir, "benign_bytes.txt")

    with open(malware_path, 'w') as f:
        f.write("\n".join(malware_samples))

    with open(benign_path, 'w') as f:
        f.write("\n".join(benign_samples))

    print(f"\nProcesamiento completado. Muestras malware: {len(malware_samples)}, benignas: {len(benign_samples)}")

if __name__ == "__main__":
    process_ember_dataset()