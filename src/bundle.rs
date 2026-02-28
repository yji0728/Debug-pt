use anyhow::{anyhow, Context, Result};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

const REQUIRED: [&str; 3] = [
    "meta.json",
    "modules/module_map.json",
    "trace/trace_events.jsonl",
];

pub fn resolve_bundle_root(bundle_input: &Path, workdir: &Path) -> Result<PathBuf> {
    let root = if bundle_input.is_dir() {
        bundle_input.to_path_buf()
    } else if bundle_input.extension().and_then(|x| x.to_str()) == Some("zip") {
        let extract = workdir.join("unzipped_bundle");
        if extract.exists() {
            fs::remove_dir_all(&extract).ok();
        }
        fs::create_dir_all(&extract)?;
        extract_zip(bundle_input, &extract)?;
        extract
    } else {
        return Err(anyhow!("bundle input must be a directory or .zip"));
    };

    let root = if root.join("bundle").is_dir() {
        root.join("bundle")
    } else {
        root
    };

    for req in REQUIRED {
        if !root.join(req).exists() {
            return Err(anyhow!("bundle missing required file: {req}"));
        }
    }
    Ok(root)
}

fn extract_zip(zip_path: &Path, to: &Path) -> Result<()> {
    let file = File::open(zip_path).with_context(|| format!("open zip {}", zip_path.display()))?;
    let mut archive = ZipArchive::new(file)?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let outpath = to.join(entry.name());
        if entry.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut outfile = File::create(&outpath)?;
            io::copy(&mut entry, &mut outfile)?;
        }
    }
    Ok(())
}
