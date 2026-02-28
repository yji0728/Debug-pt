use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct StateIngest {
    pub event_count: usize,
    pub thread_count: usize,
    pub module_count: usize,
    pub capture_mode: String,
    pub bundle_schema: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct TopFunction {
    pub function: String,
    pub hotness: u64,
    pub fan_in: usize,
    pub fan_out: usize,
}

#[derive(Debug, Serialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct CallGraph {
    pub edges: Vec<Edge>,
    pub top_functions: Vec<TopFunction>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CfgFeature {
    pub function: String,
    pub branch_count: u64,
    pub indirect_branch_ratio: f64,
    pub switch_like: bool,
    pub flattening_suspect: bool,
    pub opaque_predicate_suspect: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct TimelineItem {
    pub ts: Option<u64>,
    pub tid: Option<u64>,
    pub kind: String,
    pub function: String,
    pub api: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct FunctionLabel {
    pub function: String,
    pub label: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct FinalReport {
    pub top_functions: Vec<TopFunction>,
    pub function_labels: Vec<FunctionLabel>,
    pub obfuscation_highlights: Vec<CfgFeature>,
    pub behavior_timeline: Vec<TimelineItem>,
}
