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
use std::{
  fs::{File, OpenOptions},
  io::{BufReader, Write},
  time::Instant,
};

type E = Bn256EngineBivariateKZG;
type F = halo2curves::bn256::Fr;
type EE = nova_snark::provider::chopin::EvaluationEngine<E>;

const NUM_ITERATIONS: usize = 3;
const KZG_KEY_DIR: &str = "bivariatekzg-setup";

fn main() {
  init_chopin_timings_csv();

  for log_n in 15..20 {
    let n = 1 << log_n;

    let setup_start = Instant::now();
    let path = format!("{KZG_KEY_DIR}/ck_{log_n}");
    let file = OpenOptions::new()
      .read(true)
      .open(&path)
      .unwrap_or_else(|_| {
        panic!("missing setup file at {path}; run bivariatekzg_test_setup first")
      });
    let mut reader = BufReader::new(file);
    let ck = <E as Engine>::CE::load_setup(&mut reader, b"choptin_test", n).unwrap();
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    println!("Running benchmarks for log_n = {}", log_n);

    let mut prover_total_times = Vec::new();
    let mut verifier_total_times = Vec::new();
    let mut pi_times = Vec::new();
    let mut g_times = Vec::new();
    let mut h_times = Vec::new();
    let mut batch_times = Vec::new();
    let mut pairing_times = Vec::new();

    for _ in 0..NUM_ITERATIONS {
      ChopinTiming::reset();

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

      prover_total_times.push(prover_time.as_secs_f64() * 1000.0);
      verifier_total_times.push(verifier_time.as_secs_f64() * 1000.0);
      pairing_times.push(timings.pairing_operations_ms);
      pi_times.push(timings.commit_pi_ms);
      g_times.push(timings.commit_g_ms);
      h_times.push(timings.commit_h_ms);
      batch_times.push(timings.commit_batch_proof_ms);
    }

    let prover_avg = prover_total_times.iter().sum::<f64>() / prover_total_times.len() as f64;
    let verifier_avg = verifier_total_times.iter().sum::<f64>() / verifier_total_times.len() as f64;
    let pairing_avg = pairing_times.iter().sum::<f64>() / pairing_times.len() as f64;

    let pi_avg = pi_times.iter().sum::<f64>() / pi_times.len() as f64;
    let g_avg = g_times.iter().sum::<f64>() / g_times.len() as f64;
    let h_avg = h_times.iter().sum::<f64>() / h_times.len() as f64;
    let batch_avg = batch_times.iter().sum::<f64>() / batch_times.len() as f64;

    save_chopin_timing_row((
      log_n,
      n,
      setup_ms,
      prover_avg,
      verifier_avg,
      pairing_avg,
      pi_avg,
      g_avg,
      h_avg,
      batch_avg
    ));
  }

}

fn init_chopin_timings_csv() {
  let mut file = File::create("chopin_bench.csv").expect("Failed to create benchmark CSV file");

  writeln!(
    file,
    "log_n,n,setup_ms,prover_ms,verifier_ms,pairing_operations_ms,commit_pi_ms,commit_g_ms,commit_h_ms,commit_batch_proof_ms"
  )
  .expect("Failed to write CSV header");
}

fn save_chopin_timing_row(row: (usize, usize, f64, f64, f64, f64, f64, f64, f64, f64)) {
  let mut file = std::fs::OpenOptions::new()
    .append(true)
    .open("chopin_bench.csv")
    .expect("Failed to open benchmark CSV file");

  let (log_n, n, setup, prover, verifier, pairing, pi, g, h, batch) = row;

  writeln!(
    file,
    "{},{},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4}",
    log_n,
    n,
    setup,
    prover,
    verifier,
    pairing,
    pi,
    g,
    h,
    batch,
  )
  .expect("Failed to write benchmark row");
}