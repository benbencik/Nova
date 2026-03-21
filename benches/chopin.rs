use ff::Field;
use nova_snark::{
  provider::{chopin::ChopinTiming, Bn256EngineBivariateKZG},
  spartan::polys::multilinear::MultilinearPolynomial,
  traits::{
    commitment::CommitmentEngineTrait, evaluation::EvaluationEngineTrait, Engine,
    TranscriptEngineTrait,
  },
};
use rand_core::OsRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{fs::File, io::Write, time::Instant};

type E = Bn256EngineBivariateKZG;
type F = halo2curves::bn256::Fr;
type EE = nova_snark::provider::chopin::EvaluationEngine<E>;

const SIZES: &[usize] = &[8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
const NUM_ITERATIONS: usize = 5;

fn main() {
  println!("Chopin Benchmark");
  println!("====================================\n");

  let mut prover_results = Vec::new();
  let mut verifier_results = Vec::new();
  let mut commitment_timings = Vec::new();

  for &log_n in SIZES.iter() {
    let n = 1 << log_n;
    let setup_n = if log_n % 2 == 1 { 1 << (log_n + 1) } else { n };
    let ck = <<E as Engine>::CE as CommitmentEngineTrait<E>>::CommitmentKey::setup_from_rng(
      b"test", setup_n, OsRng,
    );
    
    println!("\nRunning benchmarks for log_n = {}, n = {}", log_n, n);

    let mut prover_total_times = Vec::new();
    let mut division_times = Vec::new();
    let mut verifier_total_times = Vec::new();
    let mut pairing_times = Vec::new();

    let mut pi_times = Vec::new();
    let mut g_times = Vec::new();
    let mut h_times = Vec::new();
    let mut batch_times = Vec::new();

    for _ in 0..NUM_ITERATIONS {
      let poly_coeffs = (0..n)
        .into_par_iter()
        .map(|_| F::random(OsRng))
        .collect::<Vec<_>>();
      let point = (0..log_n).map(|_| F::random(OsRng)).collect::<Vec<_>>();

      let (pk, vk) = EE::setup(&ck).unwrap();

      let eval = MultilinearPolynomial::new(poly_coeffs.clone()).evaluate(&point);

      let comm = <E as Engine>::CE::commit(&ck, &poly_coeffs, &F::ZERO);

      // prover --------------------------------------------------------
      let start = Instant::now();
      let mut transcript = <E as Engine>::TE::new(b"chopin_bench");
      let arg = EE::prove(
        &ck,
        &pk,
        &mut transcript,
        &comm,
        &poly_coeffs,
        &point,
        &eval,
      )
      .unwrap();
      let prover_time = start.elapsed();

      // verifier ------------------------------------------------------
      let start = Instant::now();
      let mut transcript = <E as Engine>::TE::new(b"chopin_bench");
      EE::verify(&vk, &mut transcript, &comm, &point, &eval, &arg).unwrap();
      let verifier_time = start.elapsed();

      let timings = ChopinTiming::get();
      let division_time = timings.gq_poly_construction_ms;
      let pairing_time = timings.pairing_operations_ms;

      pi_times.push(timings.commit_pi_ms);
      g_times.push(timings.commit_g_ms);
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

    let pi_avg = pi_times.iter().sum::<f64>() / pi_times.len() as f64;
    let g_avg = g_times.iter().sum::<f64>() / g_times.len() as f64;
    let h_avg = h_times.iter().sum::<f64>() / h_times.len() as f64;
    let batch_avg = batch_times.iter().sum::<f64>() / batch_times.len() as f64;
    let pi_pct = (pi_avg / prover_avg) * 100.0;
    let g_pct = (g_avg / prover_avg) * 100.0;
    let h_pct = (h_avg / prover_avg) * 100.0;
    let batch_pct = (batch_avg / prover_avg) * 100.0;

    commitment_timings.push((
      log_n, n, prover_avg, pi_avg, g_avg, h_avg, batch_avg, pi_pct, g_pct, h_pct, batch_pct,
    ));

    prover_results.push((log_n, n, prover_avg, division_avg, division_pct));
    verifier_results.push((log_n, n, verifier_avg, pairing_avg, pairing_pct));
    println!("Prover Results: {:?}", prover_avg);
  }

  save_commitment_timings(&commitment_timings);
  save_prover_time(&commitment_timings); 
}

#[allow(dead_code)]
fn save_commitment_timings(
  results: &[(usize, usize, f64, f64, f64, f64, f64, f64, f64, f64, f64)],
) {
  let mut file = File::create("chopin_commitment_timings.csv")
    .expect("Failed to create commitment timings file");

  writeln!(file, "log_n,n,total_prover_ms,commit_pi_ms,commit_g_ms,commit_h_ms,commit_batch_proof_ms,commit_pi_pct,commit_g_pct,commit_h_pct,commit_batch_proof_pct")
    .expect("Failed to write header");

  for (log_n, n, total, pi, g, h, batch, pi_pct, g_pct, h_pct, batch_pct) in results {
    writeln!(
      file,
      "{},{},{:.4},{:.4},{:.4},{:.4},{:.4},{:.2},{:.2},{:.2},{:.2}",
      log_n, n, total, pi, g, h, batch, pi_pct, g_pct, h_pct, batch_pct
    )
    .expect("Failed to write commitment timing result");
  }
}

#[allow(dead_code)]
fn save_prover_time(
  results: &[(usize, usize, f64, f64, f64, f64, f64, f64, f64, f64, f64)],
) {
  let mut file = File::create("chopin_prover_times.csv")
    .expect("Failed to create prover times file");

  writeln!(file, "log_n,n,total_prover_ms,commit_pi_ms")
    .expect("Failed to write header");

  for (log_n, n, total, pi, g, h, batch, pi_pct, g_pct, h_pct, batch_pct) in results {
    writeln!(
      file,
      "{},{},{:.4},{:.4}",
      log_n, n, total, pi
    )
    .expect("Failed to write prover time result");
  }
}
