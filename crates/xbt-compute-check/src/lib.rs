//! The first step of the compute alpha, before any model runs: what testers' machines have, how
//! well they reach each other, and which mixture-of-experts models that group could run together.
//!
//! * [`hardware`] reads what this machine has. Nothing leaves the machine from there.
//! * [`probe`] measures links between testers over iroh, and sends the results to a collector.
//! * [`plan`] turns reports and links into an answer per model: enough machines yet, and if not,
//!   what is missing.
//! * [`simulate`] makes up a group of testers from a stated mix, to see the plan's answer before
//!   there are testers. Its output is an illustration, never a measurement.
//! * [`chain`] carries a chain's TCP connections between machines over iroh: the next step, once
//!   a model runs.

pub mod chain;
pub mod hardware;
pub mod plan;
pub mod probe;
pub mod simulate;

use serde::{Deserialize, Serialize};

/// The version of the records this tool writes.
pub const SCHEMA: u32 = 1;

/// One graphics card.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Gpu {
    /// `nvidia` or `amd`.
    pub vendor: String,
    pub name: String,
    pub vram_gib: f64,
}

/// What one machine has, as the tester sends it. It names no person, host or address, and is the
/// tester's word: nothing here is proved.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub schema: u32,
    /// The link key made for this run: a tester's next run has another.
    pub id: String,
    /// A region as the tester words it, if any.
    pub region: String,
    pub arch: String,
    /// Physical cores.
    pub cores: u32,
    pub ram_total_gib: f64,
    pub ram_available_gib: f64,
    pub gpus: Vec<Gpu>,
    /// Free disk where models would go.
    pub disk_free_gib: f64,
    /// Sequential read of a file not in memory, if the tester ran the disk test.
    pub disk_read_mb_s: Option<f64>,
}

/// What one tester measured to another. Throughput is what this tester sent and received.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LinkResult {
    pub from: String,
    pub to: String,
    /// True when the path was straight between the two; false through a relay.
    pub direct: bool,
    pub rtt_ms: f64,
    pub up_mbit_s: f64,
    pub down_mbit_s: f64,
}

/// One line of the collector's file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum Record {
    Report(Report),
    Link(LinkResult),
}
