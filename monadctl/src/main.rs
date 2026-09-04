use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use monad_research::{compile_plan, prepare_evidence_bundle, ExperimentPack};

#[derive(Debug, Parser)]
#[command(
    name = "monadctl",
    version,
    about = "Validate and seal reproducible Monad experiment packs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate an experiment pack and print its canonical SHA-256 identity.
    Validate { pack: PathBuf },
    /// Compile a validated pack into a deterministic execution plan.
    Plan {
        pack: PathBuf,
        #[arg(long)]
        compact: bool,
    },
    /// Create the immutable preparation records for an evidence bundle.
    Prepare {
        pack: PathBuf,
        output: PathBuf,
        #[arg(
            long,
            default_value = "qualification/source-manifest.sha256",
            value_name = "FILE"
        )]
        source_digest: PathBuf,
    },
}

fn load(path: &PathBuf) -> Result<ExperimentPack, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Validate { pack } => {
            let pack = load(&pack)?;
            let plan = compile_plan(&pack)?;
            println!("valid {} {}", plan.experiment_id, plan.pack_sha256);
        }
        Command::Plan { pack, compact } => {
            let pack = load(&pack)?;
            let plan = compile_plan(&pack)?;
            if compact {
                println!("{}", serde_json::to_string(&plan)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            }
        }
        Command::Prepare {
            pack,
            output,
            source_digest,
        } => {
            let pack = load(&pack)?;
            let recorded_source_digest = fs::read_to_string(source_digest)?;
            let manifest = prepare_evidence_bundle(&pack, &output, recorded_source_digest.trim())?;
            println!("prepared {} {}", output.display(), manifest.pack_sha256);
        }
    }
    Ok(())
}
