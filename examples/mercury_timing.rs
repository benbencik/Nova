//! Example demonstrating Mercury performance timing instrumentation
//!
//! Run with: cargo run --release --features mercury-timing --example mercury_timing

use ff::Field;
use nova_snark::{
  provider::Bn256EngineKZG,
  traits::{commitment::CommitmentEngineTrait, evaluation::EvaluationEngineTrait, Engine, TranscriptEngineTrait},
};
use rand_core::OsRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

#[cfg(feature = "mercury-timing")]
use nova_snark::provider::mercury_timing;

type E = Bn256EngineKZG;
type EE = nova_snark::provider::mercury::EvaluationEngine<E>;
type F = halo2curves::bn256::Fr;

fn main() {
  println!("Mercury Performance Timing Demo");
  println!("================================\n");
  println!("Note: This example demonstrates the timing instrumentation.");
  println!("The actual proof/verify is skipped to keep the example simple.\n");

  // Initialize timing collector
  #[cfg(feature = "mercury-timing")]
  mercury_timing::init_timing();

  // Test with a single polynomial size
  let log_n = 14;
  println!("Testing with log_n = {} (n = {})", log_n, 1 << log_n);
  
  #[cfg(feature = "mercury-timing")]
  mercury_timing::clear_timing();

  // Run some polynomial operations that will be timed
  test_polynomial_operations(log_n);
  
  #[cfg(feature = "mercury-timing")]
  {
    println!("\nTiming Results:");
    println!("--------------");
    
    let entries = mercury_timing::get_timing_entries();
    
    if entries.is_empty() {
      println!("No timing data collected. Make sure you compiled with --features mercury-timing");
      return;
    }
    
    // Group by section and compute statistics
    use std::collections::HashMap;
    let mut stats: HashMap<String, Vec<u64>> = HashMap::new();
    
    for entry in &entries {
      stats.entry(entry.section.clone())
        .or_insert_with(Vec::new)
        .push(entry.duration_us);
    }
    
    // Sort by total time
    let mut sorted_stats: Vec<_> = stats.iter().collect();
    sorted_stats.sort_by_key(|(_, times)| std::cmp::Reverse(times.iter().sum::<u64>()));
    
    println!("\n{:<50} {:<15} {:<10} {:<15}", "Section", "Total (ms)", "Count", "Avg (ms)");
    println!("{}", "-".repeat(90));
    
    for (section, times) in sorted_stats {
      let total_ms = times.iter().sum::<u64>() as f64 / 1000.0;
      let count = times.len();
      let avg_ms = total_ms / count as f64;
      
      println!("{:<50} {:<15.2} {:<10} {:<15.2}", 
               section, total_ms, count, avg_ms);
    }
    
    println!("\nTo get complete timing data for prove/verify, run the full test suite:");
    println!("  cargo test --release --features mercury-timing mercury::tests");
  }
  
  #[cfg(not(feature = "mercury-timing"))]
  {
    println!("Timing feature is not enabled.");
    println!("Rebuild with: cargo run --release --features mercury-timing --example mercury_timing");
  }
}

fn test_polynomial_operations(log_n: usize) {
  let n = 1 << log_n;
  
  println!("Generating random polynomial with {} coefficients...", n);
  let poly_coeffs: Vec<F> = (0..n)
    .into_par_iter()
    .map(|_| F::random(OsRng))
    .collect();
    
  let _point: Vec<F> = (0..log_n).map(|_| F::random(OsRng)).collect();

  println!("Setting up commitment key...");
  let ck = <<E as Engine>::CE as CommitmentEngineTrait<E>>::CommitmentKey::setup_from_rng(
    b"test", n, OsRng,
  );

  println!("Computing commitment...");
  let _comm = <E as Engine>::CE::commit(&ck, &poly_coeffs, &F::ZERO);

  println!("Done! Check timing results above.");
  println!("\nFor full prove/verify timing, the mercury tests instrument all major operations:");
  println!("- FFT operations (forward and inverse)");
  println!("- Multi-scalar multiplications (MSMs)");
  println!("- Polynomial divisions and computations");
  println!("- Batch evaluation arguments");
  println!("- Pairing checks");
}