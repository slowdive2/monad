use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EXPERIMENT_PACK_SCHEMA_VERSION: u32 = 1;
pub const EVIDENCE_MANIFEST_SCHEMA_VERSION: u32 = 1;
const PAGE_SIZE: u64 = 0x1000;
const DEFAULT_APERTURE_LIMIT: u64 = 1 << 39;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExperimentPack {
    pub schema_version: u32,
    pub experiment_id: String,
    pub research_question: String,
    pub hypothesis: String,
    pub source_sha256: String,
    pub machine: MachineSelector,
    pub launch: LaunchPlan,
    pub views: Vec<ViewPlan>,
    pub schedule: Vec<ActivationStep>,
    pub trigger: Trigger,
    pub expected_outcomes: Vec<ExpectedOutcome>,
    pub repetitions: u32,
    pub stop: StopConditions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MachineSelector {
    pub machine_id: String,
    pub windows_build: String,
    pub cpu_model: String,
    pub microcode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LaunchPlan {
    /// zero selects monad's documented default limit.
    pub aperture_limit: u64,
    pub rendezvous_timeout_tsc: u64,
    /// complete translated device-resource ranges that extend the ram-derived
    /// physical inventory.
    pub device_ranges: Vec<DeviceRange>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceRange {
    pub start: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ViewPlan {
    pub name: String,
    pub source: String,
    pub edits: Vec<ViewEdit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ViewEdit {
    SetPermissions {
        gpa: u64,
        length: u64,
        permissions: u8,
    },
    RestoreFromBase {
        gpa: u64,
        length: u64,
    },
    MapBacking4k {
        gpa: u64,
        length: u64,
        artifact: String,
        artifact_sha256: String,
        permissions: u8,
        memory_type: u8,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivationStep {
    pub view: String,
    pub cpu_dense_indices: Vec<u16>,
    pub dwell_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    pub program: String,
    pub args: Vec<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedOutcome {
    pub name: String,
    pub oracle: String,
    pub predicate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StopConditions {
    pub max_failures: u32,
    pub max_dropped_events: u64,
    pub abort_on_fatal: bool,
    pub max_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExecutionPlan {
    pub schema_version: u32,
    pub experiment_id: String,
    pub pack_sha256: String,
    pub source_sha256: String,
    pub repetitions: u32,
    pub total_activation_steps: u64,
    pub view_build_order: Vec<String>,
    pub activation_order: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EvidenceManifest {
    pub schema_version: u32,
    pub status: String,
    pub experiment_id: String,
    pub pack_sha256: String,
    pub source_sha256: String,
    pub generated_unix_ms: u128,
    pub tool: String,
    pub machine: MachineSelector,
    pub repetitions: u32,
    pub total_activation_steps: u64,
    pub required_records: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    pub path: String,
    pub message: String,
}

#[derive(Debug)]
pub enum ResearchError {
    InvalidPack(Vec<ValidationIssue>),
    SourceDigestMismatch { pack: String, recorded: String },
    Io(std::io::Error),
    Json(serde_json::Error),
    Clock,
}

impl fmt::Display for ResearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPack(issues) => {
                writeln!(formatter, "experiment pack has {} error(s):", issues.len())?;
                for issue in issues {
                    writeln!(formatter, "{}: {}", issue.path, issue.message)?;
                }
                Ok(())
            }
            Self::SourceDigestMismatch { pack, recorded } => write!(
                formatter,
                "pack source digest {pack} does not match recorded source digest {recorded}"
            ),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Json(error) => write!(formatter, "{error}"),
            Self::Clock => write!(formatter, "system clock is before the Unix epoch"),
        }
    }
}

impl std::error::Error for ResearchError {}

impl From<std::io::Error> for ResearchError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ResearchError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

fn issue(issues: &mut Vec<ValidationIssue>, path: impl Into<String>, message: impl Into<String>) {
    issues.push(ValidationIssue {
        path: path.into(),
        message: message.into(),
    });
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_range(issues: &mut Vec<ValidationIssue>, path: &str, start: u64, length: u64) {
    if start & (PAGE_SIZE - 1) != 0 {
        issue(issues, format!("{path}.gpa"), "must be 4 KiB aligned");
    }
    if length == 0 || length & (PAGE_SIZE - 1) != 0 {
        issue(
            issues,
            format!("{path}.length"),
            "must be a nonzero multiple of 4 KiB",
        );
    }
    if start.checked_add(length).is_none() {
        issue(issues, path, "range overflows u64");
    }
}

fn validate_permissions(issues: &mut Vec<ValidationIssue>, path: &str, permissions: u8) {
    if permissions & !0b111 != 0 {
        issue(
            issues,
            path,
            "only read/write/execute bits 0..2 are defined",
        );
    }
    if permissions & 0b010 != 0 && permissions & 0b001 == 0 {
        issue(
            issues,
            path,
            "EPT write permission requires read permission",
        );
    }
}

pub fn validate(pack: &ExperimentPack) -> Result<(), ResearchError> {
    let mut issues = Vec::new();
    if pack.schema_version != EXPERIMENT_PACK_SCHEMA_VERSION {
        issue(
            &mut issues,
            "schema_version",
            format!("must be {EXPERIMENT_PACK_SCHEMA_VERSION}"),
        );
    }
    if !valid_id(&pack.experiment_id) {
        issue(
            &mut issues,
            "experiment_id",
            "must be 1..128 ASCII letters, digits, '.', '-', or '_'",
        );
    }
    for (path, value) in [
        ("research_question", pack.research_question.as_str()),
        ("hypothesis", pack.hypothesis.as_str()),
        ("machine.machine_id", pack.machine.machine_id.as_str()),
        ("machine.windows_build", pack.machine.windows_build.as_str()),
        ("machine.cpu_model", pack.machine.cpu_model.as_str()),
        ("machine.microcode", pack.machine.microcode.as_str()),
    ] {
        if value.trim().is_empty() {
            issue(&mut issues, path, "must not be empty");
        }
    }
    if !valid_sha256(&pack.source_sha256) {
        issue(
            &mut issues,
            "source_sha256",
            "must be 64 lowercase hexadecimal characters",
        );
    }
    if pack.launch.rendezvous_timeout_tsc == 0 {
        issue(
            &mut issues,
            "launch.rendezvous_timeout_tsc",
            "must be nonzero",
        );
    }
    if pack.launch.aperture_limit != 0
        && (pack.launch.aperture_limit & (PAGE_SIZE - 1) != 0
            || pack.launch.aperture_limit > (1u64 << 48))
    {
        issue(
            &mut issues,
            "launch.aperture_limit",
            "must be zero or a 4 KiB-aligned value no greater than 2^48",
        );
    }

    let effective_limit = if pack.launch.aperture_limit == 0 {
        DEFAULT_APERTURE_LIMIT
    } else {
        pack.launch.aperture_limit
    };
    let mut sorted_devices = pack.launch.device_ranges.clone();
    sorted_devices.sort_unstable_by_key(|range| range.start);
    let mut previous_end = None;
    for (index, range) in sorted_devices.iter().enumerate() {
        let path = format!("launch.device_ranges[{index}]");
        if range.start & (PAGE_SIZE - 1) != 0
            || range.length == 0
            || range.length & (PAGE_SIZE - 1) != 0
        {
            issue(
                &mut issues,
                &path,
                "start and nonzero length must be 4 KiB aligned",
            );
        }
        match range.start.checked_add(range.length) {
            None => issue(&mut issues, &path, "range overflows u64"),
            Some(end) => {
                if end > effective_limit {
                    issue(
                        &mut issues,
                        &path,
                        "range exceeds the configured aperture limit",
                    );
                }
                if previous_end.is_some_and(|prior| range.start < prior) {
                    issue(&mut issues, &path, "device ranges must not overlap");
                }
                previous_end = Some(end);
            }
        }
    }

    let mut names = HashSet::new();
    names.insert("base".to_owned());
    for (view_index, view) in pack.views.iter().enumerate() {
        let view_path = format!("views[{view_index}]");
        if !valid_id(&view.name) || view.name == "base" {
            issue(
                &mut issues,
                format!("{view_path}.name"),
                "must be a unique identifier other than 'base'",
            );
        } else if !names.insert(view.name.clone()) {
            issue(
                &mut issues,
                format!("{view_path}.name"),
                "duplicates an earlier view",
            );
        }
        if !names.contains(&view.source) {
            issue(
                &mut issues,
                format!("{view_path}.source"),
                "must name base or a previously defined view",
            );
        }
        if view.edits.is_empty() {
            issue(
                &mut issues,
                format!("{view_path}.edits"),
                "must contain at least one edit",
            );
        }
        for (edit_index, edit) in view.edits.iter().enumerate() {
            let edit_path = format!("{view_path}.edits[{edit_index}]");
            match edit {
                ViewEdit::SetPermissions {
                    gpa,
                    length,
                    permissions,
                } => {
                    validate_range(&mut issues, &edit_path, *gpa, *length);
                    validate_permissions(
                        &mut issues,
                        &format!("{edit_path}.permissions"),
                        *permissions,
                    );
                }
                ViewEdit::RestoreFromBase { gpa, length } => {
                    validate_range(&mut issues, &edit_path, *gpa, *length);
                }
                ViewEdit::MapBacking4k {
                    gpa,
                    length,
                    artifact,
                    artifact_sha256,
                    permissions,
                    memory_type,
                } => {
                    validate_range(&mut issues, &edit_path, *gpa, *length);
                    validate_permissions(
                        &mut issues,
                        &format!("{edit_path}.permissions"),
                        *permissions,
                    );
                    if artifact.trim().is_empty() {
                        issue(
                            &mut issues,
                            format!("{edit_path}.artifact"),
                            "must not be empty",
                        );
                    }
                    if !valid_sha256(artifact_sha256) {
                        issue(
                            &mut issues,
                            format!("{edit_path}.artifact_sha256"),
                            "must be 64 lowercase hexadecimal characters",
                        );
                    }
                    if *memory_type != 6 {
                        issue(
                            &mut issues,
                            format!("{edit_path}.memory_type"),
                            "cached backing remaps require memory type 6 (write-back)",
                        );
                    }
                }
            }
        }
    }

    if pack.schedule.is_empty() {
        issue(
            &mut issues,
            "schedule",
            "must contain at least one activation step",
        );
    }
    for (index, step) in pack.schedule.iter().enumerate() {
        let path = format!("schedule[{index}]");
        if !names.contains(&step.view) {
            issue(
                &mut issues,
                format!("{path}.view"),
                "must name base or a defined view",
            );
        }
        if step.cpu_dense_indices.is_empty() {
            issue(
                &mut issues,
                format!("{path}.cpu_dense_indices"),
                "must not be empty",
            );
        }
        let mut prior = None;
        for cpu in &step.cpu_dense_indices {
            if *cpu >= 256 {
                issue(
                    &mut issues,
                    format!("{path}.cpu_dense_indices"),
                    "CPU indices must be below Monad's 256-vCPU limit",
                );
            }
            if prior.is_some_and(|value| *cpu <= value) {
                issue(
                    &mut issues,
                    format!("{path}.cpu_dense_indices"),
                    "must be sorted and unique",
                );
                break;
            }
            prior = Some(*cpu);
        }
    }

    if pack.trigger.program.trim().is_empty() {
        issue(&mut issues, "trigger.program", "must not be empty");
    }
    if pack.trigger.timeout_ms == 0 {
        issue(&mut issues, "trigger.timeout_ms", "must be nonzero");
    }
    if pack.expected_outcomes.is_empty() {
        issue(
            &mut issues,
            "expected_outcomes",
            "must define at least one falsifiable outcome",
        );
    }
    let mut outcomes = HashSet::new();
    for (index, outcome) in pack.expected_outcomes.iter().enumerate() {
        if !valid_id(&outcome.name) || !outcomes.insert(outcome.name.clone()) {
            issue(
                &mut issues,
                format!("expected_outcomes[{index}].name"),
                "must be a unique identifier",
            );
        }
        if outcome.oracle.trim().is_empty() || outcome.predicate.trim().is_empty() {
            issue(
                &mut issues,
                format!("expected_outcomes[{index}]"),
                "oracle and predicate must not be empty",
            );
        }
    }
    if !(1..=10_000).contains(&pack.repetitions) {
        issue(&mut issues, "repetitions", "must be in 1..=10000");
    }
    if pack.stop.max_failures == 0 || pack.stop.max_failures > pack.repetitions {
        issue(
            &mut issues,
            "stop.max_failures",
            "must be in 1..=repetitions",
        );
    }
    if pack.stop.max_duration_ms < pack.trigger.timeout_ms {
        issue(
            &mut issues,
            "stop.max_duration_ms",
            "must be at least trigger.timeout_ms",
        );
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(ResearchError::InvalidPack(issues))
    }
}

pub fn canonical_bytes(pack: &ExperimentPack) -> Result<Vec<u8>, ResearchError> {
    validate(pack)?;
    Ok(serde_json::to_vec(pack)?)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn compile_plan(pack: &ExperimentPack) -> Result<ExecutionPlan, ResearchError> {
    let canonical = canonical_bytes(pack)?;
    let total_activation_steps = u64::from(pack.repetitions)
        .checked_mul(pack.schedule.len() as u64)
        .ok_or_else(|| {
            ResearchError::InvalidPack(vec![ValidationIssue {
                path: "schedule".to_owned(),
                message: "activation step count overflows u64".to_owned(),
            }])
        })?;
    Ok(ExecutionPlan {
        schema_version: EXPERIMENT_PACK_SCHEMA_VERSION,
        experiment_id: pack.experiment_id.clone(),
        pack_sha256: sha256_hex(&canonical),
        source_sha256: pack.source_sha256.clone(),
        repetitions: pack.repetitions,
        total_activation_steps,
        view_build_order: pack.views.iter().map(|view| view.name.clone()).collect(),
        activation_order: pack.schedule.iter().map(|step| step.view.clone()).collect(),
    })
}

pub fn prepare_evidence_bundle(
    pack: &ExperimentPack,
    output: &Path,
    recorded_source_digest: &str,
) -> Result<EvidenceManifest, ResearchError> {
    let plan = compile_plan(pack)?;
    if !valid_sha256(recorded_source_digest) || recorded_source_digest != pack.source_sha256 {
        return Err(ResearchError::SourceDigestMismatch {
            pack: pack.source_sha256.clone(),
            recorded: recorded_source_digest.to_owned(),
        });
    }
    let generated_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ResearchError::Clock)?
        .as_millis();
    let manifest = EvidenceManifest {
        schema_version: EVIDENCE_MANIFEST_SCHEMA_VERSION,
        status: "prepared-not-executed".to_owned(),
        experiment_id: pack.experiment_id.clone(),
        pack_sha256: plan.pack_sha256,
        source_sha256: pack.source_sha256.clone(),
        generated_unix_ms,
        tool: format!("monadctl {}", env!("CARGO_PKG_VERSION")),
        machine: pack.machine.clone(),
        repetitions: pack.repetitions,
        total_activation_steps: plan.total_activation_steps,
        required_records: vec![
            "capabilities.json".to_owned(),
            "activation-history.jsonl".to_owned(),
            "events.bin".to_owned(),
            "event-loss.json".to_owned(),
            "trigger-results.jsonl".to_owned(),
            "outcomes.json".to_owned(),
        ],
    };

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(output)?;
    fs::write(
        output.join("experiment-pack.canonical.json"),
        canonical_bytes(pack)?,
    )?;
    fs::write(
        output.join("evidence-manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack() -> ExperimentPack {
        ExperimentPack {
            schema_version: EXPERIMENT_PACK_SCHEMA_VERSION,
            experiment_id: "permission-ab".to_owned(),
            research_question: "Does removing write permission cause the expected EPT exit?"
                .to_owned(),
            hypothesis: "The treatment view produces a write violation.".to_owned(),
            source_sha256: "1".repeat(64),
            machine: MachineSelector {
                machine_id: "lab-a".to_owned(),
                windows_build: "test-build".to_owned(),
                cpu_model: "test-cpu".to_owned(),
                microcode: "test-microcode".to_owned(),
            },
            launch: LaunchPlan {
                aperture_limit: DEFAULT_APERTURE_LIMIT,
                rendezvous_timeout_tsc: 100,
                device_ranges: vec![DeviceRange {
                    start: 0xfec0_0000,
                    length: PAGE_SIZE,
                }],
            },
            views: vec![ViewPlan {
                name: "read-only".to_owned(),
                source: "base".to_owned(),
                edits: vec![ViewEdit::SetPermissions {
                    gpa: 0x2000,
                    length: PAGE_SIZE,
                    permissions: 0b101,
                }],
            }],
            schedule: vec![
                ActivationStep {
                    view: "base".to_owned(),
                    cpu_dense_indices: vec![0],
                    dwell_ms: 10,
                },
                ActivationStep {
                    view: "read-only".to_owned(),
                    cpu_dense_indices: vec![0],
                    dwell_ms: 10,
                },
            ],
            trigger: Trigger {
                program: "ground-truth-trigger.exe".to_owned(),
                args: vec!["bounded-write".to_owned()],
                timeout_ms: 1000,
            },
            expected_outcomes: vec![ExpectedOutcome {
                name: "treatment-exit".to_owned(),
                oracle: "monad-events".to_owned(),
                predicate: "treatment has one matching write EPT violation".to_owned(),
            }],
            repetitions: 3,
            stop: StopConditions {
                max_failures: 1,
                max_dropped_events: 0,
                abort_on_fatal: true,
                max_duration_ms: 10_000,
            },
        }
    }

    #[test]
    fn valid_pack_compiles_to_stable_identity() {
        let pack = pack();
        let first = compile_plan(&pack).expect("plan");
        let reparsed: ExperimentPack =
            serde_json::from_slice(&serde_json::to_vec_pretty(&pack).expect("pretty"))
                .expect("parse");
        let second = compile_plan(&reparsed).expect("second plan");
        assert_eq!(first.pack_sha256, second.pack_sha256);
        assert_eq!(first.total_activation_steps, 6);
    }

    #[test]
    fn malformed_pack_reports_multiple_paths() {
        let mut pack = pack();
        pack.schema_version = 99;
        pack.views[0].edits = vec![ViewEdit::SetPermissions {
            gpa: 1,
            length: 0,
            permissions: 0b010,
        }];
        pack.schedule[0].cpu_dense_indices = vec![1, 1];
        let ResearchError::InvalidPack(issues) = validate(&pack).expect_err("invalid") else {
            panic!("unexpected error");
        };
        assert!(issues.iter().any(|issue| issue.path == "schema_version"));
        assert!(issues
            .iter()
            .any(|issue| issue.path.ends_with(".permissions")));
        assert!(issues
            .iter()
            .any(|issue| issue.path.ends_with(".cpu_dense_indices")));
    }

    #[test]
    fn source_digest_must_match_before_bundle_creation() {
        let pack = pack();
        let output = std::env::temp_dir().join(format!(
            "monad-research-test-{}-{}",
            std::process::id(),
            sha256_hex(pack.experiment_id.as_bytes())
        ));
        let error = prepare_evidence_bundle(&pack, &output, &"2".repeat(64)).expect_err("mismatch");
        assert!(matches!(error, ResearchError::SourceDigestMismatch { .. }));
        assert!(!output.exists());
    }

    #[test]
    fn prepared_bundle_is_explicitly_not_execution_evidence() {
        let pack = pack();
        let output = std::env::temp_dir().join(format!(
            "monad-research-success-{}-{}",
            std::process::id(),
            sha256_hex(pack.experiment_id.as_bytes())
        ));
        if output.exists() {
            fs::remove_dir_all(&output).expect("remove stale test directory");
        }
        let manifest =
            prepare_evidence_bundle(&pack, &output, &pack.source_sha256).expect("prepare");
        assert_eq!(manifest.status, "prepared-not-executed");
        assert!(output.join("experiment-pack.canonical.json").is_file());
        assert!(output.join("evidence-manifest.json").is_file());
        fs::remove_dir_all(&output).expect("remove test directory");
    }
}
