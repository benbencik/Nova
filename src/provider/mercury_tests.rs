//! Performance tests for Mercury with timing instrumentation
//!
//! These tests demonstrate the timing feature across different problem sizes.
//!
//! Run with:
//! ```
//! cargo test --release --features mercury-timing mercury_performance -- --nocapture --test-threads=1
//! ```

#[cfg(test)]
#[cfg(feature = "mercury-timing")]
mod mercury_performance_tests {
  use ff::Field;
  use rand_core::OsRng;
  use rayon::iter::{IntoParallelIterator, ParallelIterator};

  use crate::provider::mercury_timing;
  use crate::spartan::polys::multilinear::MultilinearPolynomial;
  use crate::spartan::polys::univariate::UniPoly;
  use crate::traits::commitment::CommitmentEngineTrait;
  use crate::traits::evaluation::EvaluationEngineTrait;
  use crate::traits::{Engine, TranscriptEngineTrait};
  use crate::{provider::Bn256EngineKZG, provider::mercury::EvaluationEngine};

  type F = halo2curves::bn256::Fr;
  type E = Bn256EngineKZG;
  type EE = EvaluationEngine<E>;

  fn prove_and_verify_with_timing(log_n: usize) -> (u64, u64) {
    let n = 1 << log_n;
    let poly = UniPoly {
      coeffs: (0..n)
        .into_par_iter()
        .map(|_| F::random(OsRng))
        .collect::<Vec<_>>(),
    };
    let point = (0..log_n).map(|_| F::random(OsRng)).collect::<Vec<_>>();

    let ck = <<E as Engine>::CE as CommitmentEngineTrait<E>>::CommitmentKey::setup_from_rng(
      b"test", n, OsRng,
    );

    let (pk, vk) = EE::setup(&ck);

    let eval = MultilinearPolynomial::new(poly.coeffs.clone()).evaluate(&point);

    // Time the prove phase
    mercury_timing::clear_timing();
    let prove_start = std::time::Instant::now();

    let mut transcript = <E as Engine>::TE::new(b"test");
    let comm = <E as Engine>::CE::commit(&ck, &poly.coeffs, &F::ZERO);

    let arg = EE::prove(&ck, &pk, &mut transcript, &comm, &poly.coeffs, &point, &eval).unwrap();

    let prove_time = prove_start.elapsed().as_micros() as u64;

    // Time the verify phase
    let verify_start = std::time::Instant::now();
    let mut transcript = <E as Engine>::TE::new(b"test");
    EE::verify(&vk, &mut transcript, &comm, &point, &eval, &arg).unwrap();
    let verify_time = verify_start.elapsed().as_micros() as u64;

    (prove_time, verify_time)
  }

  fn analyze_and_print_timings(test_name: &str, log_n: usize) {
    let entries = mercury_timing::get_timing_entries();

    println!("\n========================================");
    println!("Test: {} (log_n = {}, n = {})", test_name, log_n, 1 << log_n);
    println!("========================================\n");

    if entries.is_empty() {
      println!("No timing data collected!");
      return;
    }

    // Group by section and compute statistics
    use std::collections::HashMap;
    let mut stats: HashMap<String, Vec<u64>> = HashMap::new();

    for entry in &entries {
      stats
        .entry(entry.section.clone())
        .or_insert_with(Vec::new)
        .push(entry.duration_us);
    }

    // Sort by total time
    let mut sorted_stats: Vec<_> = stats.iter().collect();
    sorted_stats.sort_by_key(|(_, times)| std::cmp::Reverse(times.iter().sum::<u64>()));

    let total_time: u64 = sorted_stats.iter().map(|(_, times)| times.iter().sum::<u64>()).sum();

    println!(
      "{:<45} {:>12} {:>8} {:>12} {:>12} {:>10}",
      "Section", "Total (ms)", "Count", "Avg (ms)", "Max (ms)", "% Total"
    );
    println!("{}", "-".repeat(110));

    for (section, times) in &sorted_stats {
      let sum: u64 = times.iter().sum();
      let total_ms = sum as f64 / 1000.0;
      let count = times.len();
      let avg_ms = total_ms / count as f64;
      let max_ms = *times.iter().max().unwrap() as f64 / 1000.0;
      let percentage = (sum as f64 / total_time as f64) * 100.0;

      println!(
        "{:<45} {:>12.2} {:>8} {:>12.2} {:>12.2} {:>9.1}%",
        section, total_ms, count, avg_ms, max_ms, percentage
      );
    }

    println!("\nTotal measured time: {:.2} ms\n", total_time as f64 / 1000.0);

    // Category breakdown
    println!("Performance Breakdown by Category:");
    println!("{}", "-".repeat(50));

    let mut categories = HashMap::new();
    categories.insert("FFT Operations", 0u64);
    categories.insert("MSM/Commitments", 0u64);
    categories.insert("Polynomial Ops", 0u64);
    categories.insert("Batch Evaluation", 0u64);
    categories.insert("Pairing/Verification", 0u64);
    categories.insert("Other", 0u64);

    for (section, times) in &sorted_stats {
      let sum: u64 = times.iter().sum();
      let section_lower = section.to_lowercase();

      if section_lower.contains("fft") {
        *categories.get_mut("FFT Operations").unwrap() += sum;
      } else if section_lower.contains("msm") || section_lower.contains("commit") {
        *categories.get_mut("MSM/Commitments").unwrap() += sum;
      } else if section_lower.contains("pairing") || section_lower.contains("verify") {
        *categories.get_mut("Pairing/Verification").unwrap() += sum;
      } else if section_lower.contains("batch") {
        *categories.get_mut("Batch Evaluation").unwrap() += sum;
      } else if section_lower.contains("poly")
        || section_lower.contains("divide")
        || section_lower.contains("compute")
      {
        *categories.get_mut("Polynomial Ops").unwrap() += sum;
      } else {
        *categories.get_mut("Other").unwrap() += sum;
      }
    }

    let mut cat_vec: Vec<_> = categories.iter().collect();
    cat_vec.sort_by_key(|(_, time)| std::cmp::Reverse(**time));

    for (category, time) in cat_vec {
      let time_ms = *time as f64 / 1000.0;
      let percentage = (*time as f64 / total_time as f64) * 100.0;
      if time_ms > 0.0 {
        println!("  {:<25} {:>10.2} ms ({:>5.1}%)", category, time_ms, percentage);
      }
    }
  }

  #[test]
  fn test_mercury_timing_small_instance() {
    // Small instance: log_n = 10 (n = 1024)
    // This is the easiest instance - good for quick testing
    mercury_timing::init_timing();
    mercury_timing::clear_timing();

    let log_n = 10;
    let (prove_us, verify_us) = prove_and_verify_with_timing(log_n);

    println!("\n=== SMALL INSTANCE ===");
    println!("Prove time: {:.2} ms", prove_us as f64 / 1000.0);
    println!("Verify time: {:.2} ms", verify_us as f64 / 1000.0);

    analyze_and_print_timings("Small Instance", log_n);
  }

  #[test]
  fn test_mercury_timing_medium_instance() {
    // Medium instance: log_n = 14 (n = 16384)
    // This is a moderate instance - representative of typical usage
    mercury_timing::init_timing();
    mercury_timing::clear_timing();

    let log_n = 14;
    let (prove_us, verify_us) = prove_and_verify_with_timing(log_n);

    println!("\n=== MEDIUM INSTANCE ===");
    println!("Prove time: {:.2} ms", prove_us as f64 / 1000.0);
    println!("Verify time: {:.2} ms", verify_us as f64 / 1000.0);

    analyze_and_print_timings("Medium Instance", log_n);
  }

  #[test]
  fn test_mercury_timing_large_instance() {
    // Large instance: log_n = 16 (n = 65536)
    // This is a harder instance - stress test
    mercury_timing::init_timing();
    mercury_timing::clear_timing();

    let log_n = 16;
    let (prove_us, verify_us) = prove_and_verify_with_timing(log_n);

    println!("\n=== LARGE INSTANCE ===");
    println!("Prove time: {:.2} ms", prove_us as f64 / 1000.0);
    println!("Verify time: {:.2} ms", verify_us as f64 / 1000.0);

    analyze_and_print_timings("Large Instance", log_n);
  }

  #[test]
  fn test_mercury_timing_scaling_analysis() {
    // Scaling test: Run multiple sizes and compare
    mercury_timing::init_timing();

    println!("\n========================================");
    println!("SCALING ANALYSIS");
    println!("========================================\n");

    let sizes = vec![
      (8, "Tiny"),
      (10, "Small"),
      (12, "Medium-Small"),
      (14, "Medium"),
      (15, "Medium-Large"),
    ];

    println!(
      "{:<15} {:>10} {:>15} {:>15} {:>15}",
      "Size", "n", "Prove (ms)", "Verify (ms)", "Total (ms)"
    );
    println!("{}", "-".repeat(75));

    for (log_n, name) in sizes {
      mercury_timing::clear_timing();
      let (prove_us, verify_us) = prove_and_verify_with_timing(log_n);
      let total_us = prove_us + verify_us;

      println!(
        "{:<15} {:>10} {:>15.2} {:>15.2} {:>15.2}",
        name,
        1 << log_n,
        prove_us as f64 / 1000.0,
        verify_us as f64 / 1000.0,
        total_us as f64 / 1000.0
      );
    }

    println!("\nNote: Expected complexity:");
    println!("  Prover: O(n) field ops, 2n + O(√n) scalar muls");
    println!("  Verifier: O(log n) field ops, O(1) scalar muls, 2 pairings");
  }

  #[test]
  fn test_mercury_timing_category_breakdown_by_size() {
    // Compare category breakdowns across different sizes
    mercury_timing::init_timing();

    println!("\n========================================");
    println!("CATEGORY BREAKDOWN COMPARISON");
    println!("========================================\n");

    let sizes = vec![(10, "Small"), (14, "Medium"), (16, "Large")];

    for (log_n, name) in sizes {
      mercury_timing::clear_timing();
      let _ = prove_and_verify_with_timing(log_n);

      let entries = mercury_timing::get_timing_entries();
      let mut category_times = std::collections::HashMap::new();

      for entry in entries {
        let section_lower = entry.section.to_lowercase();
        let category = if section_lower.contains("fft") {
          "FFT"
        } else if section_lower.contains("msm") || section_lower.contains("commit") {
          "MSM"
        } else if section_lower.contains("pairing") {
          "Pairing"
        } else if section_lower.contains("poly")
          || section_lower.contains("divide")
          || section_lower.contains("compute")
        {
          "Polynomial"
        } else {
          "Other"
        };

        *category_times.entry(category).or_insert(0u64) += entry.duration_us;
      }

      let total: u64 = category_times.values().sum();
      println!("\n{} (log_n={}, n={}):", name, log_n, 1 << log_n);
      println!("{}", "-".repeat(50));

      let mut sorted: Vec<_> = category_times.iter().collect();
      sorted.sort_by_key(|(_, time)| std::cmp::Reverse(**time));

      for (category, time) in sorted {
        let pct = (*time as f64 / total as f64) * 100.0;
        println!(
          "  {:<15} {:>10.2} ms ({:>5.1}%)",
          category,
          *time as f64 / 1000.0,
          pct
        );
      }
    }

    println!("\n\nKey Insights:");
    println!("- MSM operations should dominate (60-70% of prover time)");
    println!("- FFT overhead increases with size but stays proportional");
    println!("- Verifier time should be relatively constant (dominated by pairings)");
  }
}
