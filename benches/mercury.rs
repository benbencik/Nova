use ff::Field;
use nova_snark::{
  provider::{mercury::MercuryTiming, Bn256EngineKZG},
  spartan::polys::multilinear::MultilinearPolynomial,
  traits::{
    commitment::CommitmentEngineTrait, evaluation::EvaluationEngineTrait, Engine,
    TranscriptEngineTrait,
  },
};
use rand_core::OsRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{fs::File, io::Write, time::Instant};

type E = Bn256EngineKZG;
type F = halo2curves::bn256::Fr;
type EE = nova_snark::provider::mercury::EvaluationEngine<E>;

const NUM_ITERATIONS: usize = 3;

fn main() {
  init_mercury_timings_csv();

  for log_n in 15..20 {
    let n = 1 << log_n;
    let setup_start = Instant::now();
    let ck = <<E as Engine>::CE as CommitmentEngineTrait<E>>::CommitmentKey::setup_from_rng(
      b"mercury_bench",
      n,
      OsRng,
    );
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    println!("Running benchmarks for log_n = {}", log_n);

    let mut prover_total_times = Vec::new();
    let mut verifier_total_times = Vec::new();

    let mut gq_poly_construction_times = Vec::new();
    let mut pairing_times = Vec::new();
    let mut q_times = Vec::new();
    let mut g_times = Vec::new();
    let mut h_times = Vec::new();
    let mut s_times = Vec::new();
    let mut d_times = Vec::new();
    let mut quot_f_times = Vec::new();
    let mut batch_times = Vec::new();

    for _ in 0..NUM_ITERATIONS {
      MercuryTiming::reset();

      let poly_coeffs = (0..n)
        .into_par_iter()
        .map(|_| F::random(OsRng))
        .collect::<Vec<_>>();
      let point = (0..log_n).map(|_| F::random(OsRng)).collect::<Vec<_>>();

      let (pk, vk) = EE::setup(&ck).unwrap();

      let eval = MultilinearPolynomial::new(poly_coeffs.clone()).evaluate(&point);

      let comm = <E as Engine>::CE::commit(&ck, &poly_coeffs, &F::ZERO);

      let prover_start = Instant::now();
      let mut transcript = <E as Engine>::TE::new(b"mercury_bench");
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
      let prover_time = prover_start.elapsed();

      let verifier_start = Instant::now();
      let mut transcript = <E as Engine>::TE::new(b"mercury_bench");
      EE::verify(&vk, &mut transcript, &comm, &point, &eval, &arg).unwrap();
      let verifier_time = verifier_start.elapsed();

      let timings = MercuryTiming::get();

      prover_total_times.push(prover_time.as_secs_f64() * 1000.0);
      verifier_total_times.push(verifier_time.as_secs_f64() * 1000.0);

      gq_poly_construction_times.push(timings.gq_poly_construction_ms);
      pairing_times.push(timings.pairing_operations_ms);
      q_times.push(timings.commit_q_ms);
      g_times.push(timings.commit_g_ms);
      h_times.push(timings.commit_h_ms);
      s_times.push(timings.commit_s_ms);
      d_times.push(timings.commit_d_ms);
      quot_f_times.push(timings.commit_quot_f_ms);
      batch_times.push(timings.commit_batch_proof_ms);
    }

    let prover_avg = prover_total_times.iter().sum::<f64>() / prover_total_times.len() as f64;
    let verifier_avg = verifier_total_times.iter().sum::<f64>() / verifier_total_times.len() as f64;

    let gq_poly_construction_avg =
      gq_poly_construction_times.iter().sum::<f64>() / gq_poly_construction_times.len() as f64;
    let pairing_avg = pairing_times.iter().sum::<f64>() / pairing_times.len() as f64;
    let q_avg = q_times.iter().sum::<f64>() / q_times.len() as f64;
    let g_avg = g_times.iter().sum::<f64>() / g_times.len() as f64;
    let h_avg = h_times.iter().sum::<f64>() / h_times.len() as f64;
    let s_avg = s_times.iter().sum::<f64>() / s_times.len() as f64;
    let d_avg = d_times.iter().sum::<f64>() / d_times.len() as f64;
    let quot_f_avg = quot_f_times.iter().sum::<f64>() / quot_f_times.len() as f64;
    let batch_avg = batch_times.iter().sum::<f64>() / batch_times.len() as f64;

    save_mercury_timing_row((
      log_n,
      n,
      setup_ms,
      prover_avg,
      verifier_avg,
      gq_poly_construction_avg,
      pairing_avg,
      q_avg,
      g_avg,
      h_avg,
      s_avg,
      d_avg,
      quot_f_avg,
      batch_avg,
    ));
  }

}

fn init_mercury_timings_csv() {
  let mut file = File::create("mercury_bench.csv").expect("Failed to create benchmark CSV file");

  writeln!(
    file,
    "log_n,n,setup_ms,prover_ms,verifier_ms,gq_poly_construction_ms,pairing_operations_ms,commit_q_ms,commit_g_ms,commit_h_ms,commit_s_ms,commit_d_ms,commit_quot_f_ms,commit_batch_proof_ms"
  )
  .expect("Failed to write CSV header");
}

fn save_mercury_timing_row(
  row: (usize, usize, f64, f64, f64, f64, f64, f64, f64, f64, f64, f64, f64, f64),
) {
  let mut file = std::fs::OpenOptions::new()
    .append(true)
    .open("mercury_bench.csv")
    .expect("Failed to open benchmark CSV file");

  let (
    log_n,
    n,
    setup,
    prover,
    verifier,
    gq_poly_construction,
    pairing,
    q,
    g,
    h,
    s,
    d,
    quot_f,
    batch,
  ) = row;

  writeln!(
    file,
    "{},{},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4}",
    log_n,
    n,
    setup,
    prover,
    verifier,
    gq_poly_construction,
    pairing,
    q,
    g,
    h,
    s,
    d,
    quot_f,
    batch,
  )
  .expect("Failed to write benchmark row");
}
