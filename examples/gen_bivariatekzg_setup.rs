use std::{fs::OpenOptions, io::BufWriter};

use nova_snark::{
  provider::{
    bivariatekzg::{CommitmentEngine, CommitmentKey},
    Bn256EngineBivariateKZG,
  },
  traits::commitment::CommitmentEngineTrait,
};
use rand_core::OsRng;

type E = Bn256EngineBivariateKZG;

const KZG_KEY_DIR: &str = "bivariatekzg-setup";
const LABEL: &[u8; 4] = b"test";
const BUFFER_SIZE: usize = 64 * 1024;

macro_rules! timeit {
  ($e:expr) => {{
    let start = std::time::Instant::now();
    let res = $e();
    let dur = start.elapsed();
    (res, dur)
  }};
}

fn main() {
  for log_n in 20..28 {
    let n = 1 << log_n;

    let (ck, gen_dur) = timeit!(|| CommitmentKey::<E>::setup_from_rng(LABEL, n, OsRng));

    let path = format!("{}/ck_{}", KZG_KEY_DIR, log_n);
    let file = OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .open(&path)
      .unwrap();
    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, &file);

    let (_, save_dur) = timeit!(|| {
      CommitmentEngine::<E>::save_setup(&ck, &mut writer).unwrap();
    });

    println!(
      "Saved setup for log(n)={}, n={} to {} (gen={:?}, save={:?}, size={}MB)",
      log_n,
      n,
      path,
      gen_dur,
      save_dur,
      file.metadata().unwrap().len() / 1024 / 1024
    );
  }
}
