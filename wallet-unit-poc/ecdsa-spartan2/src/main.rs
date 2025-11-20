//! CLI for running the Spartan-2 Prepare and Show circuits.
//!
//! Usage examples:
//!   cargo run --release -- prepare run --input ../circom/inputs/jwt/generated.json
//!   cargo run --release -- show prove --input ../circom/inputs/show/custom.json
//!   cargo run --release -- prepare setup
//!   cargo run --release -- show verify
//!
//! Legacy aliases such as `prepare`, `show`, `prove_prepare`, `setup_show`, etc. remain available.
//!
//! Typical post-keygen flow:
//! 0. `prepare setup` and `show setup` — load proving/verification keys and witnesses for each circuit.
//! 1. `generate_shared_blinds` — derive shared blinding factors used by both circuits.
//! 2. `prove_prepare` — produce the initial Prepare proof.
//! 3. `reblind_prepare` — reblind the Prepare proof without changing its `comm_W_shared`.
//! 4. `prove_show` — produce the Show proof using the shared witness commitment.
//! 5. `reblind_show` — reblind the Show proof; the reblinded proof maintains the same `comm_W_shared` as step 3.
//!
//! Every proof emitted in this sequence (including the reblinded variants) should verify successfully.

use ecdsa_spartan2::{
    generate_shared_blinds, load_instance, load_proof, load_shared_blinds, load_witness,
    prove_circuit, prove_circuit_with_pk, reblind, reblind_with_loaded_data, run_circuit,
    save_keys, setup::PREPARE_INSTANCE, setup::PREPARE_PROOF, setup::PREPARE_PROVING_KEY,
    setup::PREPARE_VERIFYING_KEY, setup::PREPARE_WITNESS, setup::SHARED_BLINDS,
    setup::SHOW_INSTANCE, setup::SHOW_PROOF, setup::SHOW_PROVING_KEY, setup::SHOW_VERIFYING_KEY,
    setup::SHOW_WITNESS, setup_circuit_keys, setup_circuit_keys_no_save, verify_circuit,
    verify_circuit_with_loaded_data, PrepareCircuit, ShowCircuit, E,
};
use std::{env::args, fs, path::PathBuf, process, time::Instant};
use tracing::info;
use tracing_subscriber::EnvFilter;

const NUM_SHARED: usize = 1;

/// Helper function to get file size in bytes
fn get_file_size(path: &str) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[derive(Debug)]
struct BenchmarkResults {
    prepare_setup_ms: u128,
    show_setup_ms: u128,
    generate_blinds_ms: u128,
    prove_prepare_ms: u128,
    reblind_prepare_ms: u128,
    prove_show_ms: u128,
    reblind_show_ms: u128,
    verify_prepare_ms: u128,
    verify_show_ms: u128,
    // Size measurements in bytes
    prepare_proving_key_bytes: u64,
    prepare_verifying_key_bytes: u64,
    show_proving_key_bytes: u64,
    show_verifying_key_bytes: u64,
    prepare_proof_bytes: u64,
    show_proof_bytes: u64,
    prepare_witness_bytes: u64,
    show_witness_bytes: u64,
}

impl BenchmarkResults {
    fn format_size(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }

    fn print_summary(&self) {
        println!("\n╔════════════════════════════════════════════════╗");
        println!("║        BENCHMARK RESULTS SUMMARY               ║");
        println!("╠════════════════════════════════════════════════╣");
        println!("║ TIMING MEASUREMENTS                            ║");
        println!("╠════════════════════════════════════════════════╣");
        println!(
            "║ Prepare Setup:          {:>10} ms      ║",
            self.prepare_setup_ms
        );
        println!(
            "║ Show Setup:             {:>10} ms      ║",
            self.show_setup_ms
        );
        println!(
            "║ Generate Blinds:        {:>10} ms      ║",
            self.generate_blinds_ms
        );
        println!(
            "║ Prove Prepare:          {:>10} ms      ║",
            self.prove_prepare_ms
        );
        println!(
            "║ Reblind Prepare:        {:>10} ms      ║",
            self.reblind_prepare_ms
        );
        println!(
            "║ Prove Show:             {:>10} ms      ║",
            self.prove_show_ms
        );
        println!(
            "║ Reblind Show:           {:>10} ms      ║",
            self.reblind_show_ms
        );
        println!(
            "║ Verify Prepare:         {:>10} ms      ║",
            self.verify_prepare_ms
        );
        println!(
            "║ Verify Show:            {:>10} ms      ║",
            self.verify_show_ms
        );
        println!("╠════════════════════════════════════════════════╣");
        println!("║ SIZE MEASUREMENTS                              ║");
        println!("╠════════════════════════════════════════════════╣");
        println!(
            "║ Prepare Proving Key:    {:>12}       ║",
            Self::format_size(self.prepare_proving_key_bytes)
        );
        println!(
            "║ Prepare Verifying Key:  {:>12}       ║",
            Self::format_size(self.prepare_verifying_key_bytes)
        );
        println!(
            "║ Show Proving Key:       {:>12}       ║",
            Self::format_size(self.show_proving_key_bytes)
        );
        println!(
            "║ Show Verifying Key:     {:>12}       ║",
            Self::format_size(self.show_verifying_key_bytes)
        );
        println!(
            "║ Prepare Proof:          {:>12}       ║",
            Self::format_size(self.prepare_proof_bytes)
        );
        println!(
            "║ Show Proof:             {:>12}       ║",
            Self::format_size(self.show_proof_bytes)
        );
        println!(
            "║ Prepare Witness:        {:>12}       ║",
            Self::format_size(self.prepare_witness_bytes)
        );
        println!(
            "║ Show Witness:           {:>12}       ║",
            Self::format_size(self.show_witness_bytes)
        );
        println!("╚════════════════════════════════════════════════╝\n");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitKind {
    Prepare,
    Show,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitAction {
    Run,
    Setup,
    Prove,
    Verify,
    Reblind,
    GenerateSharedBlinds,
    Benchmark,
}

#[derive(Debug, Default, Clone)]
struct CommandOptions {
    input: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct ParsedCommand {
    circuit: CircuitKind,
    action: CircuitAction,
    options: CommandOptions,
}

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = args().collect();
    let command_args: &[String] = if args.len() > 1 { &args[1..] } else { &[] };

    let command = match parse_command(command_args) {
        Ok(cmd) => cmd,
        Err(err) => {
            eprintln!("Error: {}", err);
            print_usage();
            process::exit(1);
        }
    };

    match command.circuit {
        CircuitKind::Prepare => execute_prepare(command.action, command.options),
        CircuitKind::Show => execute_show(command.action, command.options),
    }
}

/// Run the complete benchmark pipeline for a given input file
fn run_complete_pipeline(input_path: Option<PathBuf>) -> BenchmarkResults {
    println!("\n╔════════════════════════════════════════════════╗");
    println!("║     STARTING COMPLETE BENCHMARK PIPELINE       ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // Step 1: Setup Prepare Circuit
    info!("Step 1/9: Setting up Prepare circuit...");
    let prepare_circuit = PrepareCircuit::new(input_path.clone());
    let t0 = Instant::now();
    let (prepare_pk, prepare_vk) = setup_circuit_keys_no_save(prepare_circuit);
    let prepare_setup_ms = t0.elapsed().as_millis();
    println!("✓ Prepare setup completed: {} ms\n", prepare_setup_ms);

    // Save Prepare keys after timing
    if let Err(e) = save_keys(
        PREPARE_PROVING_KEY,
        PREPARE_VERIFYING_KEY,
        &prepare_pk,
        &prepare_vk,
    ) {
        eprintln!("Failed to save Prepare keys: {}", e);
        std::process::exit(1);
    }

    // Step 2: Setup Show Circuit
    info!("Step 2/9: Setting up Show circuit...");
    let show_circuit = ShowCircuit::new(input_path.clone());
    let t0 = Instant::now();
    let (show_pk, show_vk) = setup_circuit_keys_no_save(show_circuit);
    let show_setup_ms = t0.elapsed().as_millis();
    println!("✓ Show setup completed: {} ms\n", show_setup_ms);

    // Save Show keys after timing
    if let Err(e) = save_keys(SHOW_PROVING_KEY, SHOW_VERIFYING_KEY, &show_pk, &show_vk) {
        eprintln!("Failed to save Show keys: {}", e);
        std::process::exit(1);
    }

    // Step 3: Generate Shared Blinds
    info!("Step 3/9: Generating shared blinds...");
    let t0 = Instant::now();
    generate_shared_blinds::<E>(SHARED_BLINDS, NUM_SHARED);
    let generate_blinds_ms = t0.elapsed().as_millis();
    println!("✓ Shared blinds generated: {} ms\n", generate_blinds_ms);

    // Note: We already have prepare_pk and show_pk from setup, no need to reload from files

    // Step 4: Prove Prepare Circuit
    info!("Step 4/9: Proving Prepare circuit...");
    let t0 = Instant::now();
    let prepare_circuit = PrepareCircuit::new(input_path.clone());
    prove_circuit_with_pk(
        prepare_circuit,
        &prepare_pk,
        PREPARE_INSTANCE,
        PREPARE_WITNESS,
        PREPARE_PROOF,
    );
    let prove_prepare_ms = t0.elapsed().as_millis();
    println!("✓ Prepare proof generated: {} ms\n", prove_prepare_ms);

    // Step 5: Reblind Prepare
    info!("Step 5/9: Reblinding Prepare proof...");
    // Load data before timing (file I/O should not be part of reblind benchmark)
    let prepare_instance = load_instance(PREPARE_INSTANCE).expect("load prepare instance failed");
    let prepare_witness = load_witness(PREPARE_WITNESS).expect("load prepare witness failed");
    let shared_blinds = load_shared_blinds::<E>(SHARED_BLINDS).expect("load shared_blinds failed");

    let t0 = Instant::now();
    reblind_with_loaded_data(
        PrepareCircuit::default(),
        &prepare_pk,
        prepare_instance,
        prepare_witness,
        &shared_blinds,
        PREPARE_INSTANCE,
        PREPARE_WITNESS,
        PREPARE_PROOF,
    );
    let reblind_prepare_ms = t0.elapsed().as_millis();
    println!("✓ Prepare proof reblinded: {} ms\n", reblind_prepare_ms);

    // Step 6: Prove Show Circuit
    info!("Step 6/9: Proving Show circuit...");
    let t0 = Instant::now();
    let show_circuit = ShowCircuit::new(input_path.clone());
    prove_circuit_with_pk(
        show_circuit,
        &show_pk,
        SHOW_INSTANCE,
        SHOW_WITNESS,
        SHOW_PROOF,
    );
    let prove_show_ms = t0.elapsed().as_millis();
    println!("✓ Show proof generated: {} ms\n", prove_show_ms);

    // Step 7: Reblind Show
    info!("Step 7/9: Reblinding Show proof...");
    // Load data before timing (file I/O should not be part of reblind benchmark)
    let show_instance = load_instance(SHOW_INSTANCE).expect("load show instance failed");
    let show_witness = load_witness(SHOW_WITNESS).expect("load show witness failed");
    // Reuse shared_blinds from Prepare step (already loaded)

    let t0 = Instant::now();
    reblind_with_loaded_data(
        ShowCircuit::default(),
        &show_pk,
        show_instance,
        show_witness,
        &shared_blinds,
        SHOW_INSTANCE,
        SHOW_WITNESS,
        SHOW_PROOF,
    );
    let reblind_show_ms = t0.elapsed().as_millis();
    println!("✓ Show proof reblinded: {} ms\n", reblind_show_ms);

    // Step 8: Verify Prepare
    info!("Step 8/9: Verifying Prepare proof...");
    // Load proof and verifying key before timing (file I/O should not be part of verify benchmark)
    let prepare_proof = load_proof(PREPARE_PROOF).expect("load prepare proof failed");
    // Reuse prepare_vk from setup step (already in memory)

    let t0 = Instant::now();
    verify_circuit_with_loaded_data(&prepare_proof, &prepare_vk);
    let verify_prepare_ms = t0.elapsed().as_millis();
    println!("✓ Prepare proof verified: {} ms\n", verify_prepare_ms);

    // Step 9: Verify Show
    info!("Step 9/9: Verifying Show proof...");
    // Load proof and verifying key before timing (file I/O should not be part of verify benchmark)
    let show_proof = load_proof(SHOW_PROOF).expect("load show proof failed");
    // Reuse show_vk from setup step (already in memory)

    let t0 = Instant::now();
    verify_circuit_with_loaded_data(&show_proof, &show_vk);
    let verify_show_ms = t0.elapsed().as_millis();
    println!("✓ Show proof verified: {} ms\n", verify_show_ms);

    // Measure file sizes
    info!("Measuring artifact sizes...");
    let prepare_proving_key_bytes = get_file_size(PREPARE_PROVING_KEY);
    let prepare_verifying_key_bytes = get_file_size(PREPARE_VERIFYING_KEY);
    let show_proving_key_bytes = get_file_size(SHOW_PROVING_KEY);
    let show_verifying_key_bytes = get_file_size(SHOW_VERIFYING_KEY);
    let prepare_proof_bytes = get_file_size(PREPARE_PROOF);
    let show_proof_bytes = get_file_size(SHOW_PROOF);
    let prepare_witness_bytes = get_file_size(PREPARE_WITNESS);
    let show_witness_bytes = get_file_size(SHOW_WITNESS);

    BenchmarkResults {
        prepare_setup_ms,
        show_setup_ms,
        generate_blinds_ms,
        prove_prepare_ms,
        reblind_prepare_ms,
        prove_show_ms,
        reblind_show_ms,
        verify_prepare_ms,
        verify_show_ms,
        prepare_proving_key_bytes,
        prepare_verifying_key_bytes,
        show_proving_key_bytes,
        show_verifying_key_bytes,
        prepare_proof_bytes,
        show_proof_bytes,
        prepare_witness_bytes,
        show_witness_bytes,
    }
}

fn execute_prepare(action: CircuitAction, options: CommandOptions) {
    match action {
        CircuitAction::Setup => {
            info!(
                input = ?options.input,
                "Setting up Spartan-2 keys for the Prepare circuit"
            );
            let circuit = PrepareCircuit::new(options.input.clone());
            setup_circuit_keys(circuit, PREPARE_PROVING_KEY, PREPARE_VERIFYING_KEY);
        }
        CircuitAction::Run => {
            let circuit = PrepareCircuit::new(options.input.clone());
            info!("Running Prepare circuit with ZK-Spartan");
            run_circuit(circuit);
        }
        CircuitAction::Prove => {
            let circuit = PrepareCircuit::new(options.input.clone());
            info!("Proving Prepare circuit with ZK-Spartan");
            prove_circuit(
                circuit,
                PREPARE_PROVING_KEY,
                PREPARE_INSTANCE,
                PREPARE_WITNESS,
                PREPARE_PROOF,
            );
        }
        CircuitAction::Verify => {
            info!("Verifying Prepare proof with ZK-Spartan");
            verify_circuit(PREPARE_PROOF, PREPARE_VERIFYING_KEY);
        }
        CircuitAction::Reblind => {
            info!("Reblind Spartan sumcheck + Hyrax PCS Prepare");
            reblind(
                PrepareCircuit::default(),
                PREPARE_PROVING_KEY,
                PREPARE_INSTANCE,
                PREPARE_WITNESS,
                PREPARE_PROOF,
                SHARED_BLINDS,
            );
        }
        CircuitAction::GenerateSharedBlinds => {
            info!("Generating shared blinds for Spartan-2 circuits");
            generate_shared_blinds::<E>(SHARED_BLINDS, NUM_SHARED);
        }
        CircuitAction::Benchmark => {
            let results = run_complete_pipeline(options.input);
            results.print_summary();
        }
    }
}

fn execute_show(action: CircuitAction, options: CommandOptions) {
    match action {
        CircuitAction::Setup => {
            info!(input = ?options.input, "Setting up Spartan-2 keys for the Show circuit");
            let circuit = ShowCircuit::new(options.input.clone());
            setup_circuit_keys(circuit, SHOW_PROVING_KEY, SHOW_VERIFYING_KEY);
        }
        CircuitAction::Run => {
            let circuit = ShowCircuit::new(options.input.clone());
            info!("Running Show circuit with ZK-Spartan");
            run_circuit(circuit);
        }
        CircuitAction::Prove => {
            let circuit = ShowCircuit::new(options.input.clone());
            info!("Proving Show circuit with ZK-Spartan");
            prove_circuit(
                circuit,
                SHOW_PROVING_KEY,
                SHOW_INSTANCE,
                SHOW_WITNESS,
                SHOW_PROOF,
            );
        }
        CircuitAction::Verify => {
            info!("Verifying Show proof with ZK-Spartan");
            verify_circuit(SHOW_PROOF, SHOW_VERIFYING_KEY);
        }
        CircuitAction::Reblind => {
            info!("Reblind Spartan sumcheck + Hyrax PCS Show");
            reblind(
                ShowCircuit::default(),
                SHOW_PROVING_KEY,
                SHOW_INSTANCE,
                SHOW_WITNESS,
                SHOW_PROOF,
                SHARED_BLINDS,
            );
        }
        CircuitAction::GenerateSharedBlinds => {
            eprintln!("Error: generate_shared_blinds is only supported for the Prepare circuit");
            process::exit(1);
        }
        CircuitAction::Benchmark => {
            let results = run_complete_pipeline(options.input);
            results.print_summary();
        }
    }
}

fn parse_command(args: &[String]) -> Result<ParsedCommand, String> {
    if args.is_empty() {
        return Err("No command provided".into());
    }

    match args[0].as_str() {
        "-h" | "--help" => {
            print_usage();
            process::exit(0);
        }
        "prepare" => parse_circuit_command(CircuitKind::Prepare, &args[1..]),
        "show" => parse_circuit_command(CircuitKind::Show, &args[1..]),
        "benchmark" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare, // Benchmark runs both circuits, but we need to pick one for the enum
            action: CircuitAction::Benchmark,
            options: parse_options(&args[1..])?,
        }),
        "setup_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Setup,
            options: parse_options(&args[1..])?,
        }),
        "setup_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Setup,
            options: parse_options(&args[1..])?,
        }),
        "prove_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Prove,
            options: parse_options(&args[1..])?,
        }),
        "prove_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Prove,
            options: parse_options(&args[1..])?,
        }),
        "verify_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Verify,
            options: ensure_no_options(&args[1..])?,
        }),
        "verify_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Verify,
            options: ensure_no_options(&args[1..])?,
        }),
        "reblind_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Reblind,
            options: ensure_no_options(&args[1..])?,
        }),
        "reblind_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Reblind,
            options: ensure_no_options(&args[1..])?,
        }),
        "generate_shared_blinds" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::GenerateSharedBlinds,
            options: ensure_no_options(&args[1..])?,
        }),
        other => Err(format!("Unknown command '{other}'")),
    }
}

fn parse_circuit_command(circuit: CircuitKind, tail: &[String]) -> Result<ParsedCommand, String> {
    if tail.is_empty() {
        return Ok(ParsedCommand {
            circuit,
            action: CircuitAction::Run,
            options: CommandOptions::default(),
        });
    }

    let first = &tail[0];
    let (action, option_start) = match first.as_str() {
        "run" => (CircuitAction::Run, 1),
        "setup" => (CircuitAction::Setup, 1),
        "prove" => (CircuitAction::Prove, 1),
        "verify" => (CircuitAction::Verify, 1),
        "reblind" => (CircuitAction::Reblind, 1),
        "generate_shared_blinds" => (CircuitAction::GenerateSharedBlinds, 1),
        "benchmark" => (CircuitAction::Benchmark, 1),
        s if s.starts_with('-') => (CircuitAction::Run, 0),
        other => {
            return Err(format!(
                "Unknown action '{other}' for {:?}. Expected one of run|setup|prove|verify|reblind|generate_shared_blinds|benchmark.",
                circuit
            ))
        }
    };

    if action == CircuitAction::GenerateSharedBlinds && circuit != CircuitKind::Prepare {
        return Err(
            "The generate_shared_blinds action is only supported for the Prepare circuit".into(),
        );
    }

    let options_slice = &tail[option_start..];
    let options = match action {
        CircuitAction::Run
        | CircuitAction::Prove
        | CircuitAction::Setup
        | CircuitAction::Benchmark => parse_options(options_slice)?,
        CircuitAction::Verify | CircuitAction::Reblind | CircuitAction::GenerateSharedBlinds => {
            ensure_no_options(options_slice)?
        }
    };

    Ok(ParsedCommand {
        circuit,
        action,
        options,
    })
}

fn ensure_no_options(args: &[String]) -> Result<CommandOptions, String> {
    if args.is_empty() {
        Ok(CommandOptions::default())
    } else {
        Err(format!("Unexpected options: {}", args.join(" ")))
    }
}

fn parse_options(args: &[String]) -> Result<CommandOptions, String> {
    let mut options = CommandOptions::default();
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        if arg == "--input" || arg == "-i" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| "Missing value for --input".to_string())?;
            options.input = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--input=") {
            if value.is_empty() {
                return Err("Missing value for --input".into());
            }
            options.input = Some(PathBuf::from(value));
        } else if arg == "--help" || arg == "-h" {
            print_usage();
            process::exit(0);
        } else {
            return Err(format!("Unknown option '{arg}'"));
        }
        index += 1;
    }

    Ok(options)
}

fn print_usage() {
    eprintln!(
        "Usage:
  ecdsa-spartan2 <prepare|show> [run|setup|prove|verify] [options]
  ecdsa-spartan2 benchmark [options]

Commands:
  benchmark            Run complete pipeline with full metrics (setup, prove, reblind, verify)
  prepare <action>     Run action on Prepare circuit
  show <action>        Run action on Show circuit

Actions:
  run                  Run the complete circuit (setup, prove, verify)
  setup                Generate proving and verifying keys
  prove                Generate proof
  verify               Verify proof
  reblind              Reblind proof
  benchmark            Run complete benchmark pipeline

Options:
  --input, -i <path>   Override the circuit input JSON (run/prove/setup/benchmark)

Examples:
  cargo run --release -- benchmark --input ../circom/inputs/jwt/generated.json
  cargo run --release -- prepare run --input ../circom/inputs/jwt/generated.json
  cargo run --release -- show prove --input ../circom/inputs/show/generated.json
  cargo run --release -- show verify

Legacy commands like `prepare`, `show`, `prove_prepare`, etc. are still supported."
    );
}
