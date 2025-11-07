//! Benchmark for Mercury evaluation engine with profiling support
//!
//! Run with:
//! ```
//! cargo bench --bench mercury_profile
//! ```
//!
//! To generate flamegraph (requires pprof2 feature):
//! ```
//! cargo bench --bench mercury_profile --features flamegraph
//! ```

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ff::Field;
use nova_snark::{
  provider::Bn256EngineKZG,
  spartan::polys::multilinear::MultilinearPolynomial,
  traits::{commitment::CommitmentEngineTrait, evaluation::EvaluationEngineTrait, Engine},
};
use rand_core::OsRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

type E = Bn256EngineKZG;
type EE = nova_snark::provider::mercury::EvaluationEngine<E>;
type F = halo2curves::bn256::Fr;

fn mercury_prove_benchmark(c: &mut Criterion) {
  let mut group = c.benchmark_group("mercury_prove");
  
  for log_n in [12, 14, 16] {
    let n = 1 << log_n;
    
    let poly_coeffs: Vec<F> = (0..n)
      .into_par_iter()
      .map(|_| F::random(OsRng))
      .collect();
      
    let point: Vec<F> = (0..log_n).map(|_| F::random(OsRng)).collect();

    let ck = <<E as Engine>::CE as CommitmentEngineTrait<E>>::CommitmentKey::setup_from_rng(
      b"bench", n, OsRng,
    );

    let (pk, _vk) = EE::setup(&ck);
    let eval = MultilinearPolynomial::new(poly_coeffs.clone()).evaluate(&point);
    let comm = <E as Engine>::CE::commit(&ck, &poly_coeffs, &F::ZERO);

    group.bench_with_input(
      BenchmarkId::new("prove", log_n),
      &log_n,
      |b, _| {
        b.iter(|| {
          let mut transcript = <E as Engine>::TE::new(b"bench");
          EE::prove(
            black_box(&ck),
            black_box(&pk),
            black_box(&mut transcript),
            black_box(&comm),
            black_box(&poly_coeffs),
            black_box(&point),
            black_box(&eval),
          )
          .unwrap()
        });
      },
    );
  }
  
  group.finish();
}

fn mercury_verify_benchmark(c: &mut Criterion) {
  let mut group = c.benchmark_group("mercury_verify");
  
  for log_n in [12, 14, 16] {
    let n = 1 << log_n;
    
    let poly_coeffs: Vec<F> = (0..n)
      .into_par_iter()
      .map(|_| F::random(OsRng))
      .collect();
      
    let point: Vec<F> = (0..log_n).map(|_| F::random(OsRng)).collect();

    let ck = <<E as Engine>::CE as CommitmentEngineTrait<E>>::CommitmentKey::setup_from_rng(
      b"bench", n, OsRng,
    );

    let (pk, vk) = EE::setup(&ck);
    let eval = MultilinearPolynomial::new(poly_coeffs.clone()).evaluate(&point);
    let comm = <E as Engine>::CE::commit(&ck, &poly_coeffs, &F::ZERO);

    let mut transcript = <E as Engine>::TE::new(b"bench");
    let arg = EE::prove(&ck, &pk, &mut transcript, &comm, &poly_coeffs, &point, &eval).unwrap();

    group.bench_with_input(
      BenchmarkId::new("verify", log_n),
      &log_n,
      |b, _| {
        b.iter(|| {
          let mut transcript = <E as Engine>::TE::new(b"bench");
          EE::verify(
            black_box(&vk),
            black_box(&mut transcript),
            black_box(&comm),
            black_box(&point),
            black_box(&eval),
            black_box(&arg),
          )
          .unwrap()
        });
      },
    );
  }
  
  group.finish();
}

#[cfg(feature = "flamegraph")]
fn profiled_benchmark(c: &mut Criterion) {
  use pprof2::criterion::{Output, PProfProfiler};
  
  let mut group = c.benchmark_group("mercury_profiled");
  group.sample_size(10);
  
  let log_n = 14;
  let n = 1 << log_n;
  
  let poly_coeffs: Vec<F> = (0..n)
    .into_par_iter()
    .map(|_| F::random(OsRng))
    .collect();
    
  let point: Vec<F> = (0..log_n).map(|_| F::random(OsRng)).collect();

  let ck = <<E as Engine>::CE as CommitmentEngineTrait<E>>::CommitmentKey::setup_from_rng(
    b"bench", n, OsRng,
  );

  let (pk, vk) = EE::setup(&ck);
  let eval = MultilinearPolynomial::new(poly_coeffs.clone()).evaluate(&point);
  let comm = <E as Engine>::CE::commit(&ck, &poly_coeffs, &F::ZERO);

  group.bench_function("prove_and_verify", |b| {
    b.iter(|| {
      let mut transcript = <E as Engine>::TE::new(b"bench");
      let arg = EE::prove(
        black_box(&ck),
        black_box(&pk),
        black_box(&mut transcript),
        black_box(&comm),
        black_box(&poly_coeffs),
        black_box(&point),
        black_box(&eval),
      )
      .unwrap();
      
      let mut transcript = <E as Engine>::TE::new(b"bench");
      EE::verify(
        black_box(&vk),
        black_box(&mut transcript),
        black_box(&comm),
        black_box(&point),
        black_box(&eval),
        black_box(&arg),
      )
      .unwrap()
    });
  });
  
  group.finish();
}

#[cfg(not(feature = "flamegraph"))]
fn profiled_benchmark(_c: &mut Criterion) {
  // No-op when flamegraph feature is not enabled
}

criterion_group! {
  name = benches;
  config = Criterion::default();
  targets = mercury_prove_benchmark, mercury_verify_benchmark, profiled_benchmark
}

criterion_main!(benches);
