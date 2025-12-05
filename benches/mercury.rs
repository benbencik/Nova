#![allow(non_snake_case)]

use ff::Field;
use nova_snark::{
  provider::{Bn256EngineKZG, mercury::MercuryTimings},
  traits::{commitment::CommitmentEngineTrait, evaluation::EvaluationEngineTrait, Engine, TranscriptEngineTrait},
};
use rand_core::OsRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{fs::File, io::Write, time::Instant};

type E = Bn256EngineKZG;
type F = halo2curves::bn256::Fr;
type EE = nova_snark::provider::mercury::EvaluationEngine<E>;

const SIZES: &[usize] = &[6, 8, 10, 12, 14, 16, 18, 20, 22]; 
const NUM_ITERATIONS: usize = 15;

fn main() {
  println!("Mercury Benchmark");
  println!("====================================\n");

  let mut prover_results = Vec::new();
  let mut verifier_results = Vec::new();
  let mut commitment_timings = Vec::new();

  for &log_n in SIZES.iter() {
    let n = 1 << log_n;
    println!("Running benchmarks for log_n = {}, n = {}", log_n, n);

    let mut prover_total_times = Vec::new();
    let mut division_times = Vec::new();
    let mut verifier_total_times = Vec::new();
    let mut pairing_times = Vec::new();

    let mut qg_times = Vec::new();
    let mut h_times = Vec::new();
    let mut batch_times = Vec::new();
    for iteration in 0..NUM_ITERATIONS {
      println!("  Iteration {}/{}", iteration + 1, NUM_ITERATIONS);

      let poly: Vec<F> = (0..n)
        .into_par_iter()
        .map(|_| F::random(OsRng))
        .collect();
      let point: Vec<F> = (0..log_n).map(|_| F::random(OsRng)).collect();

      // setup commitment key
      let ck = <<E as Engine>::CE as CommitmentEngineTrait<E>>::CommitmentKey::setup_from_rng(
        b"mercury_bench", n, OsRng,
      );

      let (pk, vk) = EE::setup(&ck);

      // compute using public helper function
      let eval = nova_snark::provider::mercury::evaluate_multilinear(&poly, &point);
      let comm = <E as Engine>::CE::commit(&ck, &poly, &F::ZERO);

      // prover --------------------------------------------------------
      let start = Instant::now();
      let mut transcript = <E as Engine>::TE::new(b"mercury_bench");
      let arg = EE::prove(&ck, &pk, &mut transcript, &comm, &poly, &point, &eval).unwrap();
      let prover_time = start.elapsed();

      // verifier ------------------------------------------------------
      let start = Instant::now();
      let mut transcript = <E as Engine>::TE::new(b"mercury_bench");
      EE::verify(&vk, &mut transcript, &comm, &point, &eval, &arg).unwrap();
      let verifier_time = start.elapsed();

      let timings = MercuryTimings::get();
      let division_time = timings.gq_poly_construction_ms;
      let pairing_time = timings.pairing_operations_ms;

      qg_times.push(timings.commit_qg_ms);
      h_times.push(timings.commit_h_ms);
      batch_times.push(timings.commit_batch_proof_ms);

      prover_total_times.push(prover_time.as_secs_f64() * 1000.0);
      division_times.push(division_time);
      verifier_total_times.push(verifier_time.as_secs_f64() * 1000.0);
      pairing_times.push(pairing_time);
    }

    let prover_avg = prover_total_times.iter().sum::<f64>() / prover_total_times.len() as f64;
    let division_avg = division_times.iter().sum::<f64>() / division_times.len() as f64;
    let verifier_avg = verifier_total_times.iter().sum::<f64>() / verifier_total_times.len() as f64;
    let pairing_avg = pairing_times.iter().sum::<f64>() / pairing_times.len() as f64;
    let division_pct = (division_avg / prover_avg) * 100.0;
    let pairing_pct = (pairing_avg / verifier_avg) * 100.0;

    let qg_avg = qg_times.iter().sum::<f64>() / qg_times.len() as f64;
    let h_avg = h_times.iter().sum::<f64>() / h_times.len() as f64;
    let batch_avg = batch_times.iter().sum::<f64>() / batch_times.len() as f64;
    let qg_pct = (qg_avg / prover_avg) * 100.0;
    let h_pct = (h_avg / prover_avg) * 100.0;
    let batch_pct = (batch_avg / prover_avg) * 100.0;

    commitment_timings.push((
      log_n,
      n,
      prover_avg,
      qg_avg,
      h_avg,
      batch_avg,
      qg_pct,
      h_pct,
      batch_pct,
    ));

    prover_results.push((log_n, n, prover_avg, division_avg, division_pct));
    verifier_results.push((log_n, n, verifier_avg, pairing_avg, pairing_pct));
  }

  save_prover_results(&prover_results);
  save_verifier_results(&verifier_results);
  save_commitment_timings(&commitment_timings);
  println!("Results saved to mercury_prover_results.csv, mercury_verifier_results.csv, and mercury_commitment_timings.csv");
fn save_commitment_timings(results: &[(usize, usize, f64, f64, f64, f64, f64, f64, f64)]) {
  let mut file = File::create("mercury_commitment_timings.csv")
    .expect("Failed to create commitment timings file");

  writeln!(file, "log_n,n,total_prover_ms,commit_qg_ms,commit_h_ms,commit_batch_proof_ms,commit_qg_pct,commit_h_pct,commit_batch_proof_pct")
    .expect("Failed to write header");

  for (log_n, n, total, qg, h, batch, qg_pct, h_pct, batch_pct) in results {
    writeln!(
      file,
      "{},{},{:.4},{:.4},{:.4},{:.4},{:.2},{:.2},{:.2}",
      log_n, n, total, qg, h, batch, qg_pct, h_pct, batch_pct
    )
    .expect("Failed to write commitment timing result");
  }
}
}

fn save_prover_results(results: &[(usize, usize, f64, f64, f64)]) {
  let mut file = File::create("mercury_prover_results.csv")
    .expect("Failed to create prover results file");

  writeln!(file, "log_n,n,total_time_ms,division_time_ms,division_percentage")
    .expect("Failed to write header");

  for (log_n, n, total_time, division_time, division_pct) in results {
    writeln!(
      file,
      "{},{},{:.4},{:.4},{:.2}",
      log_n, n, total_time, division_time, division_pct
    )
    .expect("Failed to write prover result");
  }
}

fn save_verifier_results(results: &[(usize, usize, f64, f64, f64)]) {
  let mut file = File::create("mercury_verifier_results.csv")
    .expect("Failed to create verifier results file");

  writeln!(file, "log_n,n,total_time_ms,pairing_time_ms,pairing_percentage")
    .expect("Failed to write header");

  for (log_n, n, total_time, pairing_time, pairing_pct) in results {
    writeln!(
      file,
      "{},{},{:.4},{:.4},{:.2}",
      log_n, n, total_time, pairing_time, pairing_pct
    )
    .expect("Failed to write verifier result");
  }
}
