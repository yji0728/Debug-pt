use crate::bundle::resolve_bundle_root;
use crate::report::{
    CallGraph, CfgFeature, Edge, FinalReport, FunctionLabel, StateIngest, TimelineItem, TopFunction,
};
use crate::schema::{Event, Meta, ModuleMap};
use anyhow::Result;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

pub struct RunSummary {
    pub event_count: usize,
    pub top_function_count: usize,
}

pub fn run_pipeline(bundle_input: &Path, out_dir: &Path, top_n: usize) -> Result<RunSummary> {
    fs::create_dir_all(out_dir)?;
    let bundle_root = resolve_bundle_root(bundle_input, out_dir)?;

    let meta: Meta = serde_json::from_reader(File::open(bundle_root.join("meta.json"))?)?;
    let module_map: ModuleMap =
        serde_json::from_reader(File::open(bundle_root.join("modules/module_map.json"))?)?;
    let events = read_events(&bundle_root.join("trace/trace_events.jsonl"))?;

    let mut normalized = normalize_addrs(&events, &module_map);
    attribute_events_with_callstack(&mut normalized);

    let state = ingest_state(&meta, &module_map, &normalized);
    let callgraph = build_callgraph(&normalized, top_n);
    let cfg_features = recover_cfg(&normalized);
    let timeline = behavior_timeline(&normalized);
    let labels = semantic_labels(&callgraph, &cfg_features, &normalized);
    let report = final_report(&callgraph, &cfg_features, &timeline, &labels, top_n);

    let analysis = out_dir.join("analysis");
    let reports = out_dir.join("reports");
    fs::create_dir_all(&analysis)?;
    fs::create_dir_all(&reports)?;

    write_json(&analysis.join("state_ingest.json"), &state)?;
    write_jsonl(&analysis.join("addr_norm.jsonl"), &normalized)?;
    write_json(&analysis.join("callgraph.json"), &callgraph)?;
    write_jsonl(&analysis.join("cfg_features.jsonl"), &cfg_features)?;
    write_jsonl(&analysis.join("behavior_timeline.jsonl"), &timeline)?;
    write_jsonl(&analysis.join("function_labels.jsonl"), &labels)?;
    write_json(&reports.join("report.json"), &report)?;
    write_json(&out_dir.join("fastfunc.report.json"), &report)?;

    let mut md = File::create(reports.join("report.md"))?;
    writeln!(md, "# FASTFUNC report")?;
    writeln!(md, "- top functions: {}", report.top_functions.len())?;
    writeln!(md, "- labels: {}", report.function_labels.len())?;
    writeln!(
        md,
        "- obfuscation highlights: {}",
        report.obfuscation_highlights.len()
    )?;
    writeln!(md, "\n## Behavior timeline (attributed)")?;
    writeln!(md, "| ts | tid | kind | function | api |")?;
    writeln!(md, "|---:|---:|---|---|---|")?;
    for item in report.behavior_timeline.iter().take(20) {
        writeln!(
            md,
            "| {} | {} | {} | {} | {} |",
            item.ts
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            item.tid
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            item.kind,
            item.function,
            item.api.clone().unwrap_or_else(|| "-".to_string())
        )?;
    }

    let mut compat_md = File::create(out_dir.join("fastfunc.report.md"))?;
    writeln!(compat_md, "# FASTFUNC report")?;
    writeln!(compat_md, "- top functions: {}", report.top_functions.len())?;
    writeln!(compat_md, "- labels: {}", report.function_labels.len())?;
    writeln!(
        compat_md,
        "- obfuscation highlights: {}",
        report.obfuscation_highlights.len()
    )?;
    writeln!(compat_md, "\n## Behavior timeline (attributed)")?;
    writeln!(compat_md, "| ts | tid | kind | function | api |")?;
    writeln!(compat_md, "|---:|---:|---|---|---|")?;
    for item in report.behavior_timeline.iter().take(20) {
        writeln!(
            compat_md,
            "| {} | {} | {} | {} | {} |",
            item.ts
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            item.tid
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            item.kind,
            item.function,
            item.api.clone().unwrap_or_else(|| "-".to_string())
        )?;
    }

    Ok(RunSummary {
        event_count: state.event_count,
        top_function_count: report.top_functions.len(),
    })
}

fn ingest_state(meta: &Meta, module_map: &ModuleMap, events: &[NormEvent]) -> StateIngest {
    let capture_mode = meta
        .capture_mode
        .clone()
        .or_else(|| meta.collector.as_ref().and_then(|c| c.mode.clone()))
        .unwrap_or_else(|| "unknown".to_string());

    StateIngest {
        event_count: events.len(),
        thread_count: events
            .iter()
            .filter_map(|e| e.tid)
            .collect::<HashSet<_>>()
            .len(),
        module_count: module_map.modules.len(),
        capture_mode,
        bundle_schema: meta.schema.clone().unwrap_or_else(|| "unknown".to_string()),
    }
}

#[derive(Debug, serde::Serialize)]
struct NormEvent {
    ts: Option<u64>,
    tid: Option<u64>,
    #[serde(rename = "type")]
    event_type: String,
    from: Option<String>,
    to: Option<String>,
    module_from: Option<String>,
    module_to: Option<String>,
    from_rva: Option<String>,
    to_rva: Option<String>,
    function_key: String,
    attributed_function: Option<String>,
    detail: HashMap<String, Value>,
}

fn parse_hex(addr: &str) -> Option<u64> {
    let clean = addr.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(clean, 16).ok()
}

fn normalize_addrs(events: &[Event], module_map: &ModuleMap) -> Vec<NormEvent> {
    let bases: HashMap<String, u64> = module_map
        .modules
        .iter()
        .filter_map(|m| parse_hex(&m.base).map(|b| (m.name.to_lowercase(), b)))
        .collect();

    events
        .iter()
        .map(|e| {
            let from_mod = e.module_from.clone();
            let to_mod = e.module_to.clone();
            let from_rva = rva(&e.from_addr, &from_mod, &bases);
            let to_rva = rva(&e.to_addr, &to_mod, &bases);
            let function_key = function_from(
                from_mod.clone(),
                from_rva.clone().or_else(|| e.from_addr.clone()),
            );

            NormEvent {
                ts: e.ts,
                tid: e.tid,
                event_type: e.event_type.clone(),
                from: e.from_addr.clone(),
                to: e.to_addr.clone(),
                module_from: from_mod,
                module_to: to_mod,
                from_rva,
                to_rva,
                function_key,
                attributed_function: None,
                detail: e.detail.clone(),
            }
        })
        .collect()
}

fn rva(
    addr: &Option<String>,
    module: &Option<String>,
    bases: &HashMap<String, u64>,
) -> Option<String> {
    let addr_u = addr.as_ref().and_then(|a| parse_hex(a))?;
    let base = bases.get(&module.as_ref()?.to_lowercase())?;
    Some(format!("0x{:x}", addr_u.saturating_sub(*base)))
}

fn function_from(module: Option<String>, location: Option<String>) -> String {
    format!(
        "{}!{}",
        module.unwrap_or_else(|| "?".into()),
        location.unwrap_or_else(|| "?".into())
    )
}

fn call_target_function_key(event: &NormEvent) -> String {
    function_from(
        event.module_to.clone(),
        event.to_rva.clone().or_else(|| event.to.clone()),
    )
}

fn event_owner_function(event: &NormEvent) -> String {
    event
        .attributed_function
        .clone()
        .unwrap_or_else(|| event.function_key.clone())
}

fn attribute_events_with_callstack(events: &mut [NormEvent]) {
    let mut stacks: HashMap<u64, Vec<String>> = HashMap::new();

    for event in events {
        let tid = event.tid.unwrap_or(0);
        let stack = stacks.entry(tid).or_default();

        match event.event_type.as_str() {
            "call" => {
                let caller = stack
                    .last()
                    .cloned()
                    .unwrap_or_else(|| event.function_key.clone());
                event.attributed_function = Some(caller);
                stack.push(call_target_function_key(event));
            }
            "ret" => {
                event.attributed_function = stack.last().cloned();
                let _ = stack.pop();
            }
            "api" | "syscall" | "exception" => {
                event.attributed_function = Some(
                    stack
                        .last()
                        .cloned()
                        .unwrap_or_else(|| event.function_key.clone()),
                );
            }
            _ => {
                event.attributed_function = stack.last().cloned();
            }
        }
    }
}

fn build_callgraph(events: &[NormEvent], top_n: usize) -> CallGraph {
    let mut edges: HashMap<(String, String), u64> = HashMap::new();
    let mut hotness: HashMap<String, u64> = HashMap::new();
    let mut fan_in: HashMap<String, HashSet<String>> = HashMap::new();
    let mut fan_out: HashMap<String, HashSet<String>> = HashMap::new();

    for e in events.iter().filter(|e| e.event_type == "call") {
        let src = function_from(
            e.module_from.clone(),
            e.from_rva.clone().or_else(|| e.from.clone()),
        );
        let dst = call_target_function_key(e);

        *edges.entry((src.clone(), dst.clone())).or_insert(0) += 1;
        *hotness.entry(src.clone()).or_insert(0) += 1;
        *hotness.entry(dst.clone()).or_insert(0) += 1;
        fan_out.entry(src.clone()).or_default().insert(dst.clone());
        fan_in.entry(dst.clone()).or_default().insert(src);
    }

    let mut top: Vec<TopFunction> = hotness
        .into_iter()
        .map(|(f, h)| TopFunction {
            function: f.clone(),
            hotness: h,
            fan_in: fan_in.get(&f).map(|s| s.len()).unwrap_or(0),
            fan_out: fan_out.get(&f).map(|s| s.len()).unwrap_or(0),
        })
        .collect();
    top.sort_by(|a, b| b.hotness.cmp(&a.hotness));
    top.truncate(top_n);

    let mut edge_vec: Vec<Edge> = edges
        .into_iter()
        .map(|((from, to), count)| Edge { from, to, count })
        .collect();
    edge_vec.sort_by(|a, b| b.count.cmp(&a.count));

    CallGraph {
        edges: edge_vec,
        top_functions: top,
    }
}

fn as_bool(map: &HashMap<String, Value>, key: &str) -> bool {
    map.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn as_str<'a>(map: &'a HashMap<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(|v| v.as_str())
}

fn recover_cfg(events: &[NormEvent]) -> Vec<CfgFeature> {
    #[derive(Default)]
    struct Acc {
        branches: u64,
        indirect: u64,
        targets: BTreeSet<String>,
        opaque_score: u64,
        jumptable_hits: u64,
    }

    let mut by_fn: HashMap<String, Acc> = HashMap::new();
    for e in events.iter().filter(|e| e.event_type == "branch") {
        let entry = by_fn.entry(e.function_key.clone()).or_default();
        entry.branches += 1;
        if as_bool(&e.detail, "indirect") {
            entry.indirect += 1;
        }
        if as_str(&e.detail, "kind") == Some("jumptable") {
            entry.jumptable_hits += 1;
        }
        if let Some(t) = e.to_rva.clone().or_else(|| e.to.clone()) {
            entry.targets.insert(t);
        }
        let cond = as_str(&e.detail, "cond");
        let taken_false = e.detail.get("taken").and_then(|v| v.as_bool()) == Some(false);
        if taken_false && matches!(cond, Some("je" | "jne" | "jz" | "jnz")) {
            entry.opaque_score += 1;
        }
    }

    let mut out = Vec::new();
    for (function, acc) in by_fn {
        let ratio = if acc.branches == 0 {
            0.0
        } else {
            acc.indirect as f64 / acc.branches as f64
        };
        out.push(CfgFeature {
            function,
            branch_count: acc.branches,
            indirect_branch_ratio: (ratio * 1000.0).round() / 1000.0,
            switch_like: acc.jumptable_hits > 0 || acc.targets.len() >= 3,
            flattening_suspect: ratio >= 0.3 && acc.branches >= 3,
            opaque_predicate_suspect: acc.opaque_score >= 2,
        });
    }
    out.sort_by(|a, b| b.branch_count.cmp(&a.branch_count));
    out
}

fn behavior_timeline(events: &[NormEvent]) -> Vec<TimelineItem> {
    events
        .iter()
        .filter(|e| matches!(e.event_type.as_str(), "api" | "syscall" | "exception"))
        .map(|e| TimelineItem {
            ts: e.ts,
            tid: e.tid,
            kind: e.event_type.clone(),
            function: event_owner_function(e),
            api: as_str(&e.detail, "api").map(ToOwned::to_owned),
        })
        .collect()
}

fn semantic_labels(
    callgraph: &CallGraph,
    cfg: &[CfgFeature],
    events: &[NormEvent],
) -> Vec<FunctionLabel> {
    let mut api_by_fn: HashMap<String, HashSet<String>> = HashMap::new();
    for e in events.iter().filter(|e| e.event_type == "api") {
        if let Some(api) = as_str(&e.detail, "api") {
            api_by_fn
                .entry(event_owner_function(e))
                .or_default()
                .insert(api.to_string());
        }
    }

    let mut candidates: HashSet<String> = callgraph
        .top_functions
        .iter()
        .map(|x| x.function.clone())
        .collect();
    candidates.extend(cfg.iter().map(|x| x.function.clone()));
    candidates.extend(api_by_fn.keys().cloned());

    let cfg_by_fn: HashMap<String, &CfgFeature> =
        cfg.iter().map(|c| (c.function.clone(), c)).collect();

    let mut out = Vec::new();
    for function in candidates {
        let apis = api_by_fn.get(&function).cloned().unwrap_or_default();
        let c = cfg_by_fn.get(&function).copied();
        let mut evidence = Vec::new();
        let mut label = "unknown".to_string();

        if apis.iter().any(|a| {
            a.contains("CreateFile")
                || a.contains("ReadFile")
                || a.contains("WriteFile")
                || a.contains("CloseHandle")
        }) {
            label = "file_io".to_string();
            evidence.push("file-related APIs observed".to_string());
        }
        if apis.iter().any(|a| a.contains("Reg")) {
            label = "registry_access".to_string();
            evidence.push("registry APIs observed".to_string());
        }
        if apis
            .iter()
            .any(|a| a.to_lowercase().contains("socket") || a.to_lowercase().contains("connect"))
        {
            label = "network_activity".to_string();
            evidence.push("network APIs observed".to_string());
        }
        if apis.contains("ExitProcess") {
            evidence.push("process-termination API observed".to_string());
        }
        if c.map(|x| x.switch_like).unwrap_or(false) {
            evidence.push("switch/jumptable-like branch pattern".to_string());
        }
        if c.map(|x| x.flattening_suspect).unwrap_or(false) {
            evidence.push("high indirect branch ratio".to_string());
        }

        let confidence = (0.45 + (evidence.len() as f64 * 0.1)).min(0.9);
        out.push(FunctionLabel {
            function,
            label,
            confidence: (confidence * 100.0).round() / 100.0,
            evidence,
        });
    }
    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

fn final_report(
    callgraph: &CallGraph,
    cfg: &[CfgFeature],
    timeline: &[TimelineItem],
    labels: &[FunctionLabel],
    top_n: usize,
) -> FinalReport {
    let obf: Vec<CfgFeature> = cfg
        .iter()
        .filter(|x| x.flattening_suspect || x.opaque_predicate_suspect)
        .take(top_n)
        .cloned()
        .collect();

    FinalReport {
        top_functions: callgraph
            .top_functions
            .iter()
            .take(top_n)
            .cloned()
            .collect(),
        function_labels: labels.iter().take(top_n).cloned().collect(),
        obfuscation_highlights: obf,
        behavior_timeline: timeline.iter().take(200).cloned().collect(),
    }
}

fn read_events(path: &Path) -> Result<Vec<Event>> {
    let mut out = Vec::new();
    let f = File::open(path)?;
    for line in BufReader::new(f).lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event: Event = serde_json::from_str(trimmed)?;
        out.push(event);
    }
    Ok(out)
}

fn write_json(path: &Path, v: &impl serde::Serialize) -> Result<()> {
    let f = File::create(path)?;
    serde_json::to_writer_pretty(f, v)?;
    Ok(())
}

fn write_jsonl<T: serde::Serialize>(path: &Path, lines: &[T]) -> Result<()> {
    let mut f = File::create(path)?;
    for item in lines {
        serde_json::to_writer(&mut f, item)?;
        writeln!(f)?;
    }
    Ok(())
}
