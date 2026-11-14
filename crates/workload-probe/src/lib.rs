//! Deterministic workloads shared by matched native/guest probes.
pub mod cpu;
pub mod jobs;
pub mod stats;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Throughput,
    Jobs,
    Gpu,
    Mixed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kernel {
    Integer,
    Scene,
    Memory,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub name: String,
    pub mode: Mode,
    pub kernel: Kernel,
    pub workers: usize,
    pub working_set_kib: usize,
    pub work_units: u32,
    pub gpu_iterations: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub warmup_ms: u64,
    pub sample_ms: u64,
    pub width: u32,
    pub height: u32,
    pub cases: Vec<Case>,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == 1, "unknown workload configuration schema");
        ensure!(
            (100..=5000).contains(&self.warmup_ms),
            "warmup must be 100..5000 ms"
        );
        ensure!(
            (500..=10000).contains(&self.sample_ms),
            "sample must be 500..10000 ms"
        );
        ensure!(
            (1..=24).contains(&self.cases.len()),
            "provide 1..24 workload cases"
        );
        ensure!(
            (64..=3840).contains(&self.width) && (64..=2160).contains(&self.height),
            "invalid workload dimensions"
        );
        ensure!(
            self.timeout_seconds() <= 300,
            "workload suite exceeds five-minute limit"
        );
        let mut names = std::collections::BTreeSet::new();
        for case in &self.cases {
            ensure!(
                !case.name.is_empty() && case.name.len() <= 64 && names.insert(&case.name),
                "workload names must be nonempty and unique"
            );
            ensure!(
                (1..=64).contains(&case.work_units),
                "work units must be 1..64"
            );
            ensure!(
                (1..=4096).contains(&case.gpu_iterations),
                "GPU iterations must be 1..4096"
            );
            ensure!(
                case.working_set_kib.is_power_of_two()
                    && (64..=16384).contains(&case.working_set_kib),
                "working set must be a power of two within 64..16384 KiB"
            );
            ensure!(
                case.workers <= 256 && (case.workers > 0 || case.mode == Mode::Gpu),
                "invalid CPU worker count"
            );
            ensure!(
                case.mode != Mode::Gpu || case.workers == 0,
                "GPU-only case cannot have CPU workers"
            );
            ensure!(
                case.working_set_kib * case.workers <= 512 * 1024,
                "CPU working sets exceed 512 MiB"
            );
        }
        Ok(())
    }

    pub fn timeout_seconds(&self) -> u64 {
        300 + self
            .warmup_ms
            .saturating_add(self.sample_ms)
            .saturating_mul(self.cases.len() as u64)
            .div_ceil(1000)
    }
}

#[cfg(test)]
#[path = "../tests/unit/lib.rs"]
mod tests;
