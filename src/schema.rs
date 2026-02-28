use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct Meta {
    pub schema: Option<String>,
    pub capture_mode: Option<String>,
    #[serde(default)]
    pub collector: Option<Collector>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Collector {
    pub mode: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ModuleMap {
    pub modules: Vec<ModuleRec>,
}

#[derive(Debug, Deserialize)]
pub struct ModuleRec {
    pub name: String,
    pub base: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Event {
    pub ts: Option<u64>,
    pub tid: Option<u64>,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(rename = "from")]
    pub from_addr: Option<String>,
    #[serde(rename = "to")]
    pub to_addr: Option<String>,
    pub module_from: Option<String>,
    pub module_to: Option<String>,
    #[serde(default)]
    pub detail: HashMap<String, serde_json::Value>,
}
