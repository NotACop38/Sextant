//! Stub entry point for the Sextant benchmark harness.
//!
//! Step 1 only wires up corpus loading. Running this binary loads the seed
//! corpus and prints a short summary. Accuracy scoring over the corpus is
//! implemented in a later checklist step (Step 12).

use std::process::ExitCode;

fn main() -> ExitCode {
    match bench::load_ground_truth("tlv") {
        Ok(ground_truth) => {
            println!("Sextant corpus summary");
            println!(
                "  format:     {} ({})",
                ground_truth.format, ground_truth.display_name
            );
            println!("  endianness: {}", ground_truth.endianness);
            println!(
                "  provenance: {} [{}]",
                ground_truth.provenance.origin, ground_truth.provenance.license
            );
            println!("  samples:    {}", ground_truth.samples.len());
            for sample in &ground_truth.samples {
                println!(
                    "    {} ({} bytes, {} records)",
                    sample.path, sample.size, sample.record_count
                );
            }
            eprintln!("sextant bench: accuracy scoring is not yet implemented.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("sextant bench: failed to load the corpus: {error}");
            ExitCode::FAILURE
        }
    }
}
