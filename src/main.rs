mod analyzer;
mod bundle;
mod report;
mod schema;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "fastfunc", about = "FASTFUNC native cloud analyzer")]
struct Args {
    bundle: PathBuf,
    #[arg(long, default_value = "out_fastfunc")]
    out: PathBuf,
    #[arg(long, default_value_t = 20)]
    top: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let summary = analyzer::run_pipeline(&args.bundle, &args.out, args.top)?;
    println!(
        "[ok] report generated under {} (events={}, functions={})",
        args.out.display(),
        summary.event_count,
        summary.top_function_count
    );
    Ok(())
}
