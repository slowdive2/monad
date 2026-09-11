use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use monad_research::{compile_plan, prepare_evidence_bundle, source_digest, ExperimentPack};

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
    /// hash the current source manifest, including untracked source files.
    SourceDigest {
        #[arg(default_value = ".")]
        repository: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// validate an experiment pack and print its canonical sha-256 identity.
    Validate { pack: PathBuf },
    /// summarize a statically validated plan; machine and target preflight are still required.
    Plan {
        pack: PathBuf,
        #[arg(long)]
        compact: bool,
    },
    /// create the immutable preparation records for an evidence bundle.
    Prepare {
        pack: PathBuf,
        output: PathBuf,
        #[arg(long, value_name = "FILE")]
        source_digest: PathBuf,
    },
}

fn load(path: &PathBuf) -> Result<ExperimentPack, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::SourceDigest { repository, output } => {
            let digest = source_digest(&repository)?;
            if let Some(output) = output {
                fs::write(output, format!("{digest}\n"))?;
            } else {
                println!("{digest}");
            }
        }
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
