//! CLI for running the Spartan-2 Prepare and Show circuits.
//!
//! Usage examples:
//!   cargo run --release -- prepare run --input ../circom/inputs/jwt/generated.json
//!   cargo run --release -- show prove --input ../circom/inputs/show/custom.json
//!   cargo run --release -- prepare setup
//!   cargo run --release -- show verify
//!
//! Legacy aliases such as `prepare`, `show`, `prove_prepare`, `setup_show`, etc. remain available.

use ecdsa_spartan2::{
    prove_circuit, run_circuit, set_prepare_input_path, set_show_input_path, setup::PREPARE_PROOF,
    setup::PREPARE_PROVING_KEY, setup::PREPARE_VERIFYING_KEY, setup::SHOW_PROOF,
    setup::SHOW_PROVING_KEY, setup::SHOW_VERIFYING_KEY, setup_circuit_keys, verify_circuit,
    PrepareCircuit, ShowCircuit,
};
use std::{env, path::PathBuf, process};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy)]
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

    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        process::exit(1);
    }

    let command = match parse_command(&args) {
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

fn execute_prepare(action: CircuitAction, options: CommandOptions) {
    match action {
        CircuitAction::Setup => {
            info!("Setting up Spartan-2 keys for the Prepare circuit");
            setup_circuit_keys(PrepareCircuit, PREPARE_PROVING_KEY, PREPARE_VERIFYING_KEY);
        }
        CircuitAction::Run => {
            set_prepare_input_path(options.input.clone());
            info!("Running Prepare circuit with ZK-Spartan");
            run_circuit(PrepareCircuit);
            set_prepare_input_path(Option::<PathBuf>::None);
        }
        CircuitAction::Prove => {
            set_prepare_input_path(options.input.clone());
            info!("Proving Prepare circuit with ZK-Spartan");
            prove_circuit(PrepareCircuit, PREPARE_PROVING_KEY, PREPARE_PROOF);
            set_prepare_input_path(Option::<PathBuf>::None);
        }
        CircuitAction::Verify => {
            info!("Verifying Prepare proof with ZK-Spartan");
            verify_circuit(PREPARE_PROOF, PREPARE_VERIFYING_KEY);
        }
    }
}

fn execute_show(action: CircuitAction, options: CommandOptions) {
    match action {
        CircuitAction::Setup => {
            info!("Setting up Spartan-2 keys for the Show circuit");
            setup_circuit_keys(ShowCircuit, SHOW_PROVING_KEY, SHOW_VERIFYING_KEY);
        }
        CircuitAction::Run => {
            set_show_input_path(options.input.clone());
            info!("Running Show circuit with ZK-Spartan");
            run_circuit(ShowCircuit);
            set_show_input_path(Option::<PathBuf>::None);
        }
        CircuitAction::Prove => {
            set_show_input_path(options.input.clone());
            info!("Proving Show circuit with ZK-Spartan");
            prove_circuit(ShowCircuit, SHOW_PROVING_KEY, SHOW_PROOF);
            set_show_input_path(Option::<PathBuf>::None);
        }
        CircuitAction::Verify => {
            info!("Verifying Show proof with ZK-Spartan");
            verify_circuit(SHOW_PROOF, SHOW_VERIFYING_KEY);
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
        "setup_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Setup,
            options: ensure_no_options(&args[1..])?,
        }),
        "setup_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Setup,
            options: ensure_no_options(&args[1..])?,
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
        s if s.starts_with('-') => (CircuitAction::Run, 0),
        other => {
            return Err(format!(
                "Unknown action '{other}' for {:?}. Expected one of run|setup|prove|verify.",
                circuit
            ))
        }
    };

    let options_slice = &tail[option_start..];
    let options = match action {
        CircuitAction::Setup | CircuitAction::Verify => ensure_no_options(options_slice)?,
        CircuitAction::Run | CircuitAction::Prove => parse_options(options_slice)?,
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

Options:
  --input, -i <path>   Override the circuit input JSON (run/prove only)

Examples:
  cargo run --release -- prepare run --input ../circom/inputs/jwt/generated.json
  cargo run --release -- show prove --input ../circom/inputs/show/generated.json
  cargo run --release -- show verify

Legacy commands like `prepare`, `show`, `prove_prepare`, etc. are still supported."
    );
}
