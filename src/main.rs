use rand::{Rng, seq::SliceRandom};
use rayon::prelude::*;
use std::time::Instant;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use plotters::prelude::*;
use rand::seq::IteratorRandom;


// ================= ESTRUCTURAS PRINCIPALES =================
#[derive(Debug, Clone, PartialEq)]
struct MalwareSignature {
    bytes: Vec<Option<u8>>,  // None = comodín
    score: f32,
    coverage: usize,
    false_positives: usize,
}

#[derive(Clone)]
struct Sample {
    bytes: Vec<u8>,
    is_malware: bool,
    weight: f32,
}

// ================= IMPLEMENTACIÓN DE FIRMAS =================
impl MalwareSignature {
    fn new_random(length: usize) -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes: Vec<Option<u8>> = Vec::with_capacity(length);
        let mut non_wildcard = 0;
        for _ in 0..length {
            // Asegura al menos 2 bytes concretos
            if non_wildcard < 2 || rng.gen_bool(0.7) {
                bytes.push(Some(rng.gen_range(0..=255)));
                non_wildcard += 1;
            } else {
                bytes.push(None);
            }
        }
        MalwareSignature {
            bytes,
            score: 0.0,
            coverage: 0,
            false_positives: 0,
        }
    }

    // Crear una firma a partir de una muestra real para inicialización
    fn from_sample(sample: &[u8], length: usize) -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = Vec::with_capacity(length);

        if sample.len() >= length {
            // Tomar una subsecuencia aleatoria de la muestra
            let start_pos = rng.gen_range(0..sample.len() - length + 1);
            for i in 0..length {
                // 30% de comodines, 70% byte real
                if rng.gen_bool(0.3) {
                    bytes.push(None);
                } else {
                    bytes.push(Some(sample[start_pos + i]));
                }
            }
        } else {
            // Usar toda la muestra y completar con comodines
            for &byte in sample {
                if bytes.len() < length {
                    // 30% de comodines, 70% byte real
                    if rng.gen_bool(0.3) {
                        bytes.push(None);
                    } else {
                        bytes.push(Some(byte));
                    }
                }
            }
            
            // Rellenar con comodines
            while bytes.len() < length {
                bytes.push(None);
            }
        }
        
        MalwareSignature {
            bytes,
            score: 0.0,
            coverage: 0,
            false_positives: 0,
        }
    }

    // Función de coincidencia menos estricta
    fn matches(&self, sample: &[u8]) -> bool {
        if self.bytes.len() > sample.len() {
            return false;
        }
        for window in sample.windows(self.bytes.len()) {
            if self.bytes.iter().zip(window).all(|(sig_byte, sample_byte)| {
                match sig_byte {
                    Some(b) => *b == *sample_byte,
                    None => true,
                }
            }) {
                return true;
            }
        }
        false
    }

    fn mutate(&mut self, mutation_rate: f32) {
        let mut rng = rand::thread_rng();
        for byte in &mut self.bytes {
            let action: f32 = rng.gen();
            if action < mutation_rate * 0.6 {
                *byte = Some(rng.gen_range(0..=255));
            } else if action < mutation_rate {
                *byte = None;
            }
        }
    }
}

// ================= ALGORITMO GENÉTICO =================
struct GeneticOptimizer {
    population: Vec<MalwareSignature>,
    best_fitness_history: Vec<f32>,
    stagnation_counter: usize,
}

impl GeneticOptimizer {
    fn new(population_size: usize, signature_length: usize, samples: &[Sample]) -> Self {
        let mut rng = rand::thread_rng();
        let mut population = Vec::with_capacity(population_size);

        // 40% firmas aleatorias
        for _ in 0..(population_size * 4 / 10) {
            population.push(MalwareSignature::new_random(signature_length));
        }
        // 60% firmas basadas en muestras de malware
        let malware_samples: Vec<&Sample> = samples.iter()
            .filter(|s| s.is_malware)
            .collect();
        if !malware_samples.is_empty() {
            for _ in 0..(population_size * 6 / 10) {
                let sample = malware_samples.choose(&mut rng).unwrap();
                population.push(MalwareSignature::from_sample(&sample.bytes, signature_length));
            }
        } else {
            for _ in 0..(population_size * 6 / 10) {
                population.push(MalwareSignature::new_random(signature_length));
            }
        }

        GeneticOptimizer {
            population,
            best_fitness_history: Vec::new(),
            stagnation_counter: 0,
        }
    }

    fn evolve(&mut self, samples: &[Sample], params: &GeneticParams) {
        // Evaluación paralelizada con ponderación dinámica
        self.population.par_iter_mut().for_each(|signature| {
            let mut coverage = 0;
            let mut false_positives = 0;
            let mut weighted_coverage = 0.0;

            for sample in samples {
                if signature.matches(&sample.bytes) {
                    if sample.is_malware {
                        coverage += 1;
                        weighted_coverage += sample.weight;
                    } else {
                        false_positives += 1;
                    }
                }
            }

            // Cálculo de tasas más preciso
            let total_malware = samples.iter().filter(|s| s.is_malware).count() as f32;
            let total_benign = samples.iter().filter(|s| !s.is_malware).count() as f32;
            
            let coverage_rate = if total_malware > 0.0 {
                coverage as f32 / total_malware
            } else {
                0.0
            };

            let fp_rate = if total_benign > 0.0 {
                false_positives as f32 / total_benign
            } else {
                0.0
            };
            
            // Penalizaciones más suaves
            let fp_penalty = fp_rate * 0.7;
            let wildcard_count = signature.bytes.iter().filter(|b| b.is_none()).count();
            let wildcard_ratio = wildcard_count as f32 / signature.bytes.len() as f32;
            let wildcard_penalty = wildcard_ratio * 0.2;
            let generality_penalty = if coverage_rate > 0.95 && fp_rate > 0.5 {
                0.2
            } else {
                0.0
            };

            // Nueva fórmula de fitness que prioriza precisión sobre cobertura
            signature.score = (coverage_rate * 0.8)     // Valor por detección (reducido)
                             - fp_penalty             // Mayor penalización por FPs
                             - wildcard_penalty         // Penalización por comodines
                             - generality_penalty;      // Penalización por generalidad
            
            signature.coverage = coverage;
            signature.false_positives = false_positives;
        });

        // Ordenar por mejor fitness
        self.population.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        // Registrar mejor fitness histórico
        if !self.population.is_empty() {
            let best_fitness = self.population[0].score;
            self.best_fitness_history.push(best_fitness);
        }

        // Detectar estancamiento
        if self.best_fitness_history.len() > 10 {
            let last_10: Vec<f32> = self.best_fitness_history.iter().rev().take(10).cloned().collect();
            let last_10_avg: f32 = last_10.iter().sum::<f32>() / last_10.len() as f32;
            if let Some(&best) = self.best_fitness_history.last() {
                if (best - last_10_avg).abs() < params.stagnation_threshold {
                    self.stagnation_counter += 1;
                } else {
                    self.stagnation_counter = 0;
                }
            }
        }

        // Reinicio adaptativo si hay estancamiento
        if self.stagnation_counter >= params.max_stagnation {
            println!("¡Reinicio adaptativo por estancamiento!");
            self.stagnation_counter = 0;

            // Mantener élite y regenerar el resto
            let elite = self.population[0..params.elitism_count].to_vec();
            let mut new_population = Vec::with_capacity(self.population.len());
            new_population.extend(elite);

            for _ in params.elitism_count..self.population.len() {
                new_population.push(MalwareSignature::new_random(params.signature_length));
            }

            self.population = new_population;
            return;
        }

        // Crear nueva población
        let mut new_population = Vec::with_capacity(self.population.len());

        // Elitismo: mantener los mejores individuos
        let elitism = params.elitism_count.min(self.population.len());
        new_population.extend(self.population[0..elitism].iter().cloned());

        // Selección por torneo y reproducción
        let tournament_size = 5;
        while new_population.len() < self.population.len() {
            let parent1 = self.tournament_select(tournament_size);
            let parent2 = self.tournament_select(tournament_size);

            let mut child = crossover(parent1, parent2);
            child.mutate(params.mutation_rate);
            new_population.push(child);
        }

        self.population = new_population;
    }

    fn tournament_select(&self, size: usize) -> &MalwareSignature {
        let mut rng = rand::thread_rng();

        let candidates: Vec<&MalwareSignature> = self.population
            .iter()
            .choose_multiple(&mut rng, size);

        candidates.into_iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .unwrap()
    }

    fn best_signature(&self) -> &MalwareSignature {
        &self.population[0]
    }
}

// ================= OPERADORES GENÉTICOS =================
fn crossover(parent1: &MalwareSignature, parent2: &MalwareSignature) -> MalwareSignature {
    let mut rng = rand::thread_rng();
    let crossover_point = rng.gen_range(0..parent1.bytes.len());

    let mut child_bytes = parent1.bytes[..crossover_point].to_vec();
    child_bytes.extend_from_slice(&parent2.bytes[crossover_point..]);

    MalwareSignature {
        bytes: child_bytes,
        score: 0.0,
        coverage: 0,
        false_positives: 0,
    }
}

// ================= DATASETS Y UTILIDADES =================
fn load_samples_from_file(path: impl AsRef<Path>, is_malware: bool) -> io::Result<Vec<Sample>> {
    let content = std::fs::read_to_string(path)?;
    let mut samples = Vec::new();

    for line in content.lines() {
        let bytes: Vec<u8> = line
            .split_whitespace()
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if !bytes.is_empty() {
            samples.push(Sample {
                bytes,
                is_malware,
                weight: 1.0,
            });
        }
    }

    Ok(samples)
}

fn load_ember_samples() -> io::Result<Vec<Sample>> {
    let mut samples = Vec::new();
    samples.extend(load_samples_from_file(PathBuf::from("data/processed/malware_bytes.txt"), true)?);
    samples.extend(load_samples_from_file(PathBuf::from("data/processed/benign_bytes.txt"), false)?);
    Ok(samples)
}

// Función de actualización de pesos optimizada con paralelización
fn update_sample_weights(samples: &mut [Sample], best_signature: &MalwareSignature) {
    samples.par_iter_mut().for_each(|sample| {
        if sample.is_malware && !best_signature.matches(&sample.bytes) {
            sample.weight *= 1.5;
        }
    });

    let max_weight = samples.par_iter()
        .map(|s| s.weight)
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap_or(1.0);

    samples.par_iter_mut().for_each(|sample| {
        sample.weight /= max_weight;
    });
}

// ================= VISUALIZACIÓN =================
fn plot_fitness_history(history: &[f32], filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    if history.is_empty() {
        return Err("No hay datos de fitness para graficar.".into());
    }

    let root = BitMapBackend::new(filename, (1024, 768)).into_drawing_area();
    root.fill(&WHITE)?;

    let max_fitness = *history.iter().max_by(|a,b| a.partial_cmp(b).unwrap()).unwrap();
    let min_fitness = *history.iter().min_by(|a,b| a.partial_cmp(b).unwrap()).unwrap();
    let mut min_fitness = min_fitness.min(0.0);
    let mut max_fitness = max_fitness;

    // Evitar rango nulo en Y
    if (max_fitness - min_fitness).abs() < std::f32::EPSILON {
        max_fitness = max_fitness + 0.01;
        min_fitness = min_fitness - 0.01;
    }

    let x_end = history.len() as u32;
    let font: FontDesc = ("sans-serif", 30.0).into();

    let mut chart = ChartBuilder::on(&root)
        .caption("Evolución del Fitness".to_string(), font)
        .margin(10)
        .x_label_area_size(40)
        .y_label_area_size(50)
        .build_cartesian_2d(0u32..x_end, min_fitness..max_fitness)?;

    chart.configure_mesh()
        .x_desc("Generación")
        .y_desc("Fitness")
        .draw()?;

    chart.draw_series(LineSeries::new(
        history.iter().enumerate().map(|(i, &f)| (i as u32, f)),
        &RED,
    ))?;

    root.present()?;
    Ok(())
}

// ================= CONFIGURACIÓN =================
struct GeneticParams {
    population_size: usize,
    signature_length: usize,
    generations: usize,
    mutation_rate: f32,
    elitism_count: usize,
    stagnation_threshold: f32,
    max_stagnation: usize,
}

// ================= FUNCIÓN PRINCIPAL =================
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Cargando dataset Ember 2024...");
    let mut samples = match load_ember_samples() {
        Ok(s) => {
            println!("Muestras cargadas: {} malware, {} benignos",
                     s.iter().filter(|s| s.is_malware).count(),
                     s.iter().filter(|s| !s.is_malware).count()
            );
            
            // Verificar longitud promedio de muestras
            let avg_malware_len = s.iter().filter(|s| s.is_malware)
                                 .map(|s| s.bytes.len())
                                 .sum::<usize>() as f32 
                                 / s.iter().filter(|s| s.is_malware).count() as f32;
            
            let avg_benign_len = s.iter().filter(|s| !s.is_malware)
                                .map(|s| s.bytes.len())
                                .sum::<usize>() as f32 
                                / s.iter().filter(|s| !s.is_malware).count() as f32;
            
            println!("Longitud promedio: malware={:.1} bytes, benignos={:.1} bytes", 
                     avg_malware_len, avg_benign_len);
            
            s
        },
        Err(e) => {
            eprintln!("Error cargando muestras: {}", e);
            eprintln!("Ejecute primero el script de preprocesamiento");
            return Ok(());
        }
    };
    
    // Tomar una muestra para inspección
    if let Some(sample) = samples.iter().find(|s| s.is_malware) {
        println!("Ejemplo de muestra de malware: {} bytes", sample.bytes.len());
        if !sample.bytes.is_empty() {
            print!("Primeros 16 bytes: ");
            for &b in sample.bytes.iter().take(16) {
                print!("{:02X} ", b);
            }
            println!();
        }
    }

    // Parámetros ajustados para firmas más específicas
    let params = GeneticParams {
        population_size: 400,
        signature_length: 16,
        generations: 71, // Solo 50 generaciones
        mutation_rate: 0.15,
        elitism_count: 5,
        stagnation_threshold: 0.001,
        max_stagnation: 15,
    };

    // Pasar muestras al constructor para inicialización basada en datos
    let mut optimizer = GeneticOptimizer::new(
        params.population_size,
        params.signature_length,
        &samples
    );

    println!("\nIniciando evolución de firmas...");
    let start_time = std::time::Instant::now();

    for generation in 0..params.generations {
        optimizer.evolve(&samples, &params);
        if generation % 3 == 0 {
            update_sample_weights(&mut samples, optimizer.best_signature());
        }
        if !optimizer.population.is_empty() {
            println!("Gen {}: Mejor fitness = {:.4} | Cobertura = {} | FP = {}",
                     generation,
                     optimizer.best_signature().score,
                     optimizer.best_signature().coverage,
                     optimizer.best_signature().false_positives
            );
        }
    }

    let duration = start_time.elapsed();
    println!("\nOptimización completada en {:.2?}", duration);

    // Chequeo para evitar firmas solo comodines
    if !optimizer.population.is_empty() {
        let best_sig = optimizer.best_signature();
        let non_wildcard = best_sig.bytes.iter().filter(|b| b.is_some()).count();
        if non_wildcard < 2 {
            println!("Advertencia: la mejor firma tiene demasiados comodines. Ajusta los parámetros.");
        }
        
        println!("\nMejor firma encontrada:");
        println!("Fitness: {:.4}", best_sig.score);
        
        let coverage_pct = (best_sig.coverage as f32 / samples.iter().filter(|s| s.is_malware).count() as f32) * 100.0;
        let fp_pct = (best_sig.false_positives as f32 / samples.iter().filter(|s| !s.is_malware).count() as f32) * 100.0;
        
        println!("Muestras detectadas: {} de {} ({:.2}%)", 
                 best_sig.coverage,
                 samples.iter().filter(|s| s.is_malware).count(),
                 coverage_pct);
                 
        println!("Falsos positivos: {} de {} ({:.2}%)", 
                 best_sig.false_positives,
                 samples.iter().filter(|s| !s.is_malware).count(),
                 fp_pct);
        
        // Calcular precisión y recall
        let precision = if (best_sig.coverage + best_sig.false_positives) > 0 {
            best_sig.coverage as f32 / (best_sig.coverage + best_sig.false_positives) as f32
        } else {
            0.0
        };
        
        println!("Precisión: {:.2}%", precision * 100.0);
        println!("Recall: {:.2}%", coverage_pct);
                 
        // Análisis de comodines
        let wildcard_count = best_sig.bytes.iter().filter(|b| b.is_none()).count();
        println!("Comodines: {} de {} bytes ({:.2}%)", 
                wildcard_count,
                best_sig.bytes.len(),
                (wildcard_count as f32 / best_sig.bytes.len() as f32) * 100.0);
    }

    // Mejorar el gráfico: mostrar rango completo y guardar imagen
    if let Err(e) = plot_fitness_history(&optimizer.best_fitness_history, "fitness_history.png") {
        eprintln!("Error generando gráfico: {}", e);
    } else {
        println!("Gráfico guardado en fitness_history.png");
    }

    // Verificar si hay firmas con mejor cobertura aunque tengan peor fitness
    println!("\nRevisando firmas alternativas...");
    for (i, sig) in optimizer.population.iter().take(5).enumerate() {
        println!("Firma {}: Fitness={:.4}, Cobertura={}, FP={}, Comodines={}", 
                 i,
                 sig.score,
                 sig.coverage,
                 sig.false_positives,
                 sig.bytes.iter().filter(|b| b.is_none()).count());
    }

    // Guardar la mejor firma con todos los datos relevantes
    if let Err(e) = save_signature(optimizer.best_signature(), "best_signature.txt", 
                                    samples.iter().filter(|s| s.is_malware).count(),
                                    samples.iter().filter(|s| !s.is_malware).count()) {
        eprintln!("Error guardando firma: {}", e);
    } else {
        println!("Mejor firma guardada en best_signature.txt");
    }

    Ok(())
}

fn save_signature(signature: &MalwareSignature, path: &str, total_malware: usize, total_benign: usize) -> io::Result<()> {
    let bytes_str: Vec<String> = signature.bytes.iter().map(|b| match *b {
        Some(v) => format!("{:02X}", v),
        None => "??".to_string(),
    }).collect();

    let coverage_pct = (signature.coverage as f32 / total_malware as f32) * 100.0;
    let fp_pct = (signature.false_positives as f32 / total_benign as f32) * 100.0;
    let precision = if (signature.coverage + signature.false_positives) > 0 {
        signature.coverage as f32 / (signature.coverage + signature.false_positives) as f32
    } else {
        0.0
    };
    let recall = coverage_pct;
    let wildcard_count = signature.bytes.iter().filter(|b| b.is_none()).count();
    let wildcard_pct = (wildcard_count as f32 / signature.bytes.len() as f32) * 100.0;

    let content = format!(
        "Fitness: {:.4}\nCobertura: {} de {} ({:.2}%)\nFalsos positivos: {} de {} ({:.2}%)\nPrecisión: {:.2}%\nRecall: {:.2}%\nComodines: {} de {} bytes ({:.2}%)\n\nBytes:\n{}",
        signature.score,
        signature.coverage,
        total_malware,
        coverage_pct,
        signature.false_positives,
        total_benign,
        fp_pct,
        precision * 100.0,
        recall,
        wildcard_count,
        signature.bytes.len(),
        wildcard_pct,
        bytes_str.join(" ")
    );

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;

    file.write_all(content.as_bytes())?;
    file.flush()?;
    Ok(())
}
