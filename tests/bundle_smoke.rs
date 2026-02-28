use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use tempfile::tempdir;
use zip::write::FileOptions;

fn run_cli(bundle: &Path, out: &Path) {
    let bin = env!("CARGO_BIN_EXE_fastfunc");
    let status = Command::new(bin)
        .arg(bundle)
        .arg("--out")
        .arg(out)
        .arg("--top")
        .arg("10")
        .status()
        .expect("run binary");
    assert!(status.success());
}

#[test]
fn directory_bundle_smoke() {
    let out = tempdir().unwrap();
    run_cli(Path::new("tests/fixtures/bundle"), out.path());
    assert!(out.path().join("reports/report.json").exists());
}

#[test]
fn zip_bundle_smoke_with_callstack_api_attribution() {
    let td = tempdir().unwrap();
    let root = td.path().join("gen/bundle");
    fs::create_dir_all(root.join("modules")).unwrap();
    fs::create_dir_all(root.join("trace")).unwrap();

    fs::write(
        root.join("meta.json"),
        r#"{"schema":"FASTFUNC_BUNDLE_V1","collector":{"mode":"synthetic_demo"}}"#,
    )
    .unwrap();
    fs::write(
        root.join("modules/module_map.json"),
        r#"{"modules":[{"name":"toy.exe","base":"0x400000"},{"name":"kernel32.dll","base":"0x70000000"}]}"#,
    )
    .unwrap();
    fs::write(
        root.join("trace/trace_events.jsonl"),
        "{\"ts\":1,\"tid\":1,\"type\":\"call\",\"from\":\"0x401000\",\"to\":\"0x401100\",\"module_from\":\"toy.exe\",\"module_to\":\"toy.exe\",\"detail\":{}}\n{\"ts\":2,\"tid\":1,\"type\":\"api\",\"from\":\"0x401130\",\"to\":\"0x70002000\",\"module_from\":\"toy.exe\",\"module_to\":\"kernel32.dll\",\"detail\":{\"api\":\"CreateFileW\"}}\n{\"ts\":3,\"tid\":1,\"type\":\"ret\",\"from\":\"0x401180\",\"to\":\"0x401040\",\"module_from\":\"toy.exe\",\"module_to\":\"toy.exe\",\"detail\":{}}\n",
    )
    .unwrap();

    let zip_path = td.path().join("artifact_bundle_sample.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = FileOptions::default();

    for rel in [
        "bundle/meta.json",
        "bundle/modules/module_map.json",
        "bundle/trace/trace_events.jsonl",
    ] {
        let src = td.path().join("gen").join(rel);
        zip.start_file(rel, opts).unwrap();
        let content = fs::read(src).unwrap();
        zip.write_all(&content).unwrap();
    }
    zip.finish().unwrap();

    let out = td.path().join("out");
    run_cli(&zip_path, &out);

    let report_str = fs::read_to_string(out.join("reports/report.json")).unwrap();
    let report: Value = serde_json::from_str(&report_str).unwrap();

    let labels = report["function_labels"].as_array().unwrap();
    assert!(labels.iter().any(|x| x["label"] == "file_io"));

    let timeline = report["behavior_timeline"].as_array().unwrap();
    assert_eq!(timeline[0]["function"], "toy.exe!0x1100");

    let report_md = fs::read_to_string(out.join("reports/report.md")).unwrap();
    assert!(report_md.contains("Behavior timeline (attributed)"));
}
