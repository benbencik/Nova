//! This module implements Nova's evaluation engine using Bivariate KZG, a KZG-based polynomial
//! commitment scheme for bivariate polynomials f(X, Y).
//!
//! The commitment key stores a univariate SRS {[tau^k]_1} for k = 0..n-1 along with
//! sigma_H = [tau^b]_2 where b = sqrt(n) and sigma = tau^b (implicit second trapdoor).
//! With column-major indexing (ck[j*b+i] = [tau^i sigma^j]_1), the MSM commitment equals
//! [f(tau,sigma)]_1 for the bivariate polynomial f.
#![allow(non_snake_case)]
#[cfg(feature = "io")]
use crate::provider::{ptau::PtauFileError, read_ptau, write_ptau};
use crate::{
  errors::NovaError,
  gadgets::utils::to_bignat_repr,
  provider::{
    msm::batch_add,
    traits::{DlogGroup, DlogGroupExt, PairingGroup},
  },
  traits::{
    commitment::{CommitmentEngineTrait, CommitmentTrait, Len},
    evaluation::EvaluationEngineTrait,
    evm_serde::EvmCompatSerde,
    AbsorbInRO2Trait, AbsorbInROTrait, Engine, Group, ROTrait, TranscriptReprTrait,
  },
};
use core::{
  marker::PhantomData,
  ops::Range,
  ops::{Add, Mul, MulAssign},
};
use ff::Field;
#[cfg(any(test, feature = "test-utils"))]
use ff::PrimeFieldBits;
use num_integer::Integer;
use num_traits::ToPrimitive;
#[cfg(any(test, feature = "test-utils"))]
use rand_core::OsRng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Alias to points on G1 that are in preprocessed form
type G1Affine<E> = <<E as Engine>::GE as DlogGroup>::AffineGroupElement;

/// Alias to points on G1 that are in preprocessed form
type G2Affine<E> = <<<E as Engine>::GE as PairingGroup>::G2 as DlogGroup>::AffineGroupElement;


/// KZG commitment key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentKey<E: Engine>
where
  E::GE: PairingGroup,
{
  ck: Vec<<E::GE as DlogGroup>::AffineGroupElement>,
  h: <E::GE as DlogGroup>::AffineGroupElement,
  tau_H: <<E::GE as PairingGroup>::G2 as DlogGroup>::AffineGroupElement, // needed only for the verifier key
  sigma_H: <<E::GE as PairingGroup>::G2 as DlogGroup>::AffineGroupElement, // [tau^b]_2 for bivariate KZG
}

impl<E: Engine> CommitmentKey<E>
where
  E::GE: PairingGroup,
{
  /// Create a new commitment key
  pub fn new(
    ck: Vec<<E::GE as DlogGroup>::AffineGroupElement>,
    h: <E::GE as DlogGroup>::AffineGroupElement,
    tau_H: <<E::GE as PairingGroup>::G2 as DlogGroup>::AffineGroupElement,
    sigma_H: <<E::GE as PairingGroup>::G2 as DlogGroup>::AffineGroupElement,
  ) -> Self {
    Self {
      ck,
      h,
      tau_H,
      sigma_H,
    }
  }

  /// Returns a reference to the ck field
  pub fn ck(&self) -> &[<E::GE as DlogGroup>::AffineGroupElement] {
    &self.ck
  }

  /// Returns a reference to the h field
  pub fn h(&self) -> &<E::GE as DlogGroup>::AffineGroupElement {
    &self.h
  }

  /// Returns a reference to the tau_H field
  pub fn tau_H(&self) -> &<<E::GE as PairingGroup>::G2 as DlogGroup>::AffineGroupElement {
    &self.tau_H
  }

  /// Returns a reference to the sigma_H field ([tau^b]_2 for bivariate KZG)
  pub fn sigma_H(&self) -> &<<E::GE as PairingGroup>::G2 as DlogGroup>::AffineGroupElement {
    &self.sigma_H
  }

  /// Returns the coordinates of the generator points.
  ///
  /// # Panics
  ///
  /// Panics if any generator point is the point at infinity.
  pub fn to_coordinates(&self) -> Vec<(E::Base, E::Base)> {
    self
      .ck
      .par_iter()
      .map(|c| {
        let (x, y, is_infinity) = <E::GE as DlogGroup>::group(c).to_coordinates();
        assert!(!is_infinity);
        (x, y)
      })
      .collect()
  }

  /// Compute b = 2^(floor(log2(num_gens)/2)), i.e. the floor-square-root of num_gens.
  /// Requires num_gens to be a power of 2.
  pub(crate) fn compute_b(num_gens: usize) -> usize {
    let log = usize::BITS - num_gens.leading_zeros() - 1; // log2(num_gens) for power-of-2 inputs
    1_usize << (log / 2)
  }
}

impl<E: Engine> Len for CommitmentKey<E>
where
  E::GE: PairingGroup,
{
  fn length(&self) -> usize {
    self.ck.len()
  }
}

/// A type that holds blinding generator
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DerandKey<E: Engine>
where
  E::GE: DlogGroup,
{
  #[serde_as(as = "EvmCompatSerde")]
  h: <E::GE as DlogGroup>::AffineGroupElement,
}

/// A KZG commitment
#[serde_as]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Commitment<E: Engine>
where
  E::GE: PairingGroup,
{
  #[serde_as(as = "EvmCompatSerde")]
  comm: E::GE,
}

impl<E: Engine> Commitment<E>
where
  E::GE: PairingGroup,
{
  /// Creates a new commitment from the underlying group element
  pub fn new(comm: E::GE) -> Self {
    Commitment { comm }
  }
  /// Returns the commitment as a group element
  pub fn into_inner(self) -> E::GE {
    self.comm
  }
}

impl<E: Engine> CommitmentTrait<E> for Commitment<E>
where
  E::GE: PairingGroup,
{
  fn to_coordinates(&self) -> (E::Base, E::Base, bool) {
    self.comm.to_coordinates()
  }
}

impl<E: Engine> Default for Commitment<E>
where
  E::GE: PairingGroup,
{
  fn default() -> Self {
    Commitment {
      comm: E::GE::zero(),
    }
  }
}

impl<E: Engine> TranscriptReprTrait<E::GE> for Commitment<E>
where
  E::GE: PairingGroup,
{
  fn to_transcript_bytes(&self) -> Vec<u8> {
    use crate::traits::Group;
    let (x, y, is_infinity) = self.comm.to_coordinates();
    // Get curve parameter B to determine encoding strategy
    let (_, b, _, _) = E::GE::group_params();

    if b != E::Base::ZERO {
      // For curves with B!=0 (like BN254 with B=3, Grumpkin with B=-5),
      // (0, 0) doesn't lie on the curve (since 0 != 0 + 0 + B),
      // so point at infinity can be safely encoded as (0, 0).
      let (x, y) = if is_infinity {
        (E::Base::ZERO, E::Base::ZERO)
      } else {
        (x, y)
      };
      [x.to_transcript_bytes(), y.to_transcript_bytes()].concat()
    } else {
      // For curves with B=0, (0, 0) lies on the curve, so we need the is_infinity flag
      let is_infinity_byte = (!is_infinity).into();
      [
        x.to_transcript_bytes(),
        y.to_transcript_bytes(),
        [is_infinity_byte].to_vec(),
      ]
      .concat()
    }
  }
}

impl<E: Engine> AbsorbInROTrait<E> for Commitment<E>
where
  E::GE: PairingGroup,
{
  fn absorb_in_ro(&self, ro: &mut E::RO) {
    let (x, y, is_infinity) = self.comm.to_coordinates();
    // When B != 0 (true for BN254, Grumpkin, etc.), (0,0) is not on the curve
    // so we can use it as a canonical representation for infinity.
    let (_, b, _, _) = E::GE::group_params();
    if b != E::Base::ZERO {
      let (x, y) = if is_infinity {
        (E::Base::ZERO, E::Base::ZERO)
      } else {
        (x, y)
      };
      ro.absorb(x);
      ro.absorb(y);
    } else {
      ro.absorb(x);
      ro.absorb(y);
      ro.absorb(if is_infinity {
        E::Base::ONE
      } else {
        E::Base::ZERO
      });
    }
  }
}

impl<E: Engine> AbsorbInRO2Trait<E> for Commitment<E>
where
  E::GE: PairingGroup,
{
  fn absorb_in_ro2(&self, ro: &mut E::RO2) {
    let (x, y, is_infinity) = self.comm.to_coordinates();
    // When B != 0, use (0,0) for infinity
    let (_, b, _, _) = E::GE::group_params();
    let (x, y) = if b != E::Base::ZERO && is_infinity {
      (E::Base::ZERO, E::Base::ZERO)
    } else {
      (x, y)
    };

    // we have to absorb x and y in big num format
    let limbs_x = to_bignat_repr(&x);
    let limbs_y = to_bignat_repr(&y);

    for limb in limbs_x.iter().chain(limbs_y.iter()) {
      ro.absorb(*limb);
    }
    // Only absorb is_infinity when B == 0
    if b == E::Base::ZERO {
      ro.absorb(if is_infinity {
        E::Scalar::ONE
      } else {
        E::Scalar::ZERO
      });
    }
  }
}

impl<E: Engine> MulAssign<E::Scalar> for Commitment<E>
where
  E::GE: PairingGroup,
{
  fn mul_assign(&mut self, scalar: E::Scalar) {
    let result = self.comm * scalar;
    *self = Commitment { comm: result };
  }
}

impl<'b, E: Engine> Mul<&'b E::Scalar> for &'_ Commitment<E>
where
  E::GE: PairingGroup,
{
  type Output = Commitment<E>;

  fn mul(self, scalar: &'b E::Scalar) -> Commitment<E> {
    Commitment {
      comm: self.comm * scalar,
    }
  }
}

impl<E: Engine> Mul<E::Scalar> for Commitment<E>
where
  E::GE: PairingGroup,
{
  type Output = Commitment<E>;

  fn mul(self, scalar: E::Scalar) -> Commitment<E> {
    Commitment {
      comm: self.comm * scalar,
    }
  }
}

impl<E: Engine> Add for Commitment<E>
where
  E::GE: PairingGroup,
{
  type Output = Commitment<E>;

  fn add(self, other: Commitment<E>) -> Commitment<E> {
    Commitment {
      comm: self.comm + other.comm,
    }
  }
}

/// Provides a commitment engine
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentEngine<E: Engine> {
  _p: PhantomData<E>,
}

/// Test-only methods for generating commitment keys with known tau.
/// These methods are insecure for production use - use `load_setup` with ptau files instead.
#[cfg(any(test, feature = "test-utils"))]
impl<E: Engine> CommitmentKey<E>
where
  E::GE: PairingGroup,
{
  /// NOTE: this is for testing purposes and should not be used in production.
  /// In production, use [`PublicParams::setup_with_ptau_dir`] or
  /// [`R1CSShape::commitment_key_from_ptau_dir`] with ptau files from a trusted setup ceremony.
  ///
  /// This generates a commitment key with a random tau value. Since the caller
  /// (or anyone with access to the RNG state) knows tau, this is insecure.
  pub fn setup_from_rng(label: &'static [u8], n: usize, rng: impl rand_core::RngCore) -> Self {
    const T1: usize = 1 << 16;
    const T2: usize = 100_000;

    let num_gens = n.next_power_of_two();

    let tau = E::Scalar::random(rng);

    let powers_of_tau = if num_gens < T1 {
      Self::compute_powers_serial(tau, num_gens)
    } else {
      Self::compute_powers_par(tau, num_gens)
    };

    if num_gens < T2 {
      Self::setup_from_tau_direct(label, &powers_of_tau, tau)
    } else {
      Self::setup_from_tau_fixed_base_exp(label, &powers_of_tau)
    }
  }

  fn setup_from_tau_fixed_base_exp(label: &'static [u8], powers_of_tau: &[E::Scalar]) -> Self {
    let tau = powers_of_tau[1];
    let num_gens = powers_of_tau.len();

    let gen = <E::GE as DlogGroup>::gen();

    let ck = fixed_base_exp_comb_batch::<4, 16, 64, 2, 32, _>(gen, powers_of_tau);
    let ck = ck.par_iter().map(|p| p.affine()).collect();

    let h = *E::GE::from_label(label, 1).first().unwrap();

    let tau_H = (<<E::GE as PairingGroup>::G2 as DlogGroup>::gen() * tau).affine();

    // sigma_H = [tau^b]_2 where b = sqrt(num_gens) (for bivariate KZG)
    let b = Self::compute_b(num_gens);
    let sigma_H = (<<E::GE as PairingGroup>::G2 as DlogGroup>::gen() * powers_of_tau[b]).affine();

    Self {
      ck,
      h,
      tau_H,
      sigma_H,
    }
  }

  fn setup_from_tau_direct(
    label: &'static [u8],
    powers_of_tau: &[E::Scalar],
    tau: E::Scalar,
  ) -> Self {
    let num_gens = powers_of_tau.len();

    let ck: Vec<G1Affine<E>> = (0..num_gens)
      .into_par_iter()
      .map(|i| (<E::GE as DlogGroup>::gen() * powers_of_tau[i]).affine())
      .collect();

    let h = *E::GE::from_label(label, 1).first().unwrap();

    let tau_H = (<<E::GE as PairingGroup>::G2 as DlogGroup>::gen() * tau).affine();

    // sigma_H = [tau^b]_2 where b = sqrt(num_gens) (for bivariate KZG)
    let b = Self::compute_b(num_gens);
    let sigma_H = (<<E::GE as PairingGroup>::G2 as DlogGroup>::gen() * powers_of_tau[b]).affine();

    Self {
      ck,
      h,
      tau_H,
      sigma_H,
    }
  }

  fn compute_powers_serial(tau: E::Scalar, n: usize) -> Vec<E::Scalar> {
    let mut powers_of_tau = Vec::with_capacity(n);
    powers_of_tau.insert(0, E::Scalar::ONE);
    for i in 1..n {
      powers_of_tau.insert(i, powers_of_tau[i - 1] * tau);
    }
    powers_of_tau
  }

  fn compute_powers_par(tau: E::Scalar, n: usize) -> Vec<E::Scalar> {
    let num_threads = rayon::current_num_threads();
    (0..n)
      .collect::<Vec<_>>()
      .par_chunks(std::cmp::max(n / num_threads, 1))
      .into_par_iter()
      .map(|sub_list| {
        let mut res = Vec::with_capacity(sub_list.len());
        res.push(tau.pow([sub_list[0] as u64]));
        for i in 1..sub_list.len() {
          res.push(res[i - 1] * tau);
        }
        res
      })
      .flatten()
      .collect::<Vec<_>>()
  }
}

// * Implementation of https://www.weimerskirch.org/files/Weimerskirch_FixedBase.pdf
// Only used by test-only setup code
#[cfg(any(test, feature = "test-utils"))]
fn fixed_base_exp_comb_batch<
  const H: usize,
  const POW_2_H: usize,
  const A: usize,
  const B: usize,
  const V: usize,
  G: DlogGroup,
>(
  gen: G,
  scalars: &[G::Scalar],
) -> Vec<G> {
  assert_eq!(1 << H, POW_2_H);
  assert_eq!(A, V * B);
  assert!(A <= 64);

  let zero = G::zero();
  let one = gen;

  let gi = {
    let mut res = [one; H];
    for i in 1..H {
      let prod = (0..A).fold(res[i - 1], |acc, _| acc + acc);
      res[i] = prod;
    }
    res
  };

  let mut precompute_res = (1..POW_2_H)
    .into_par_iter()
    .map(|i| {
      let mut res = [zero; V];

      // * G[0][i]
      let mut g_0_i = zero;
      for (j, item) in gi.iter().enumerate().take(H) {
        if (1 << j) & i > 0 {
          g_0_i += item;
        }
      }

      res[0] = g_0_i;

      // * G[j][i]
      for j in 1..V {
        res[j] = (0..B).fold(res[j - 1], |acc, _| acc + acc);
      }

      res
    })
    .collect::<Vec<_>>();

  precompute_res.insert(0, [zero; V]);

  let precomputed_g: [_; POW_2_H] = std::array::from_fn(|j| precompute_res[j]);

  let zero = G::zero();

  scalars
    .par_iter()
    .map(|e| {
      let mut a = zero;
      let mut bits = e.to_le_bits().into_iter().collect::<Vec<_>>();

      while bits.len() % A != 0 {
        bits.push(false);
      }

      for k in (0..B).rev() {
        a += a;
        for j in (0..V).rev() {
          let i_j_k = (0..H)
            .map(|h| {
              let b = bits[h * A + j * B + k];
              (1 << h) * b as usize
            })
            .sum::<usize>();

          if i_j_k > 0 {
            a += precomputed_g[i_j_k][j];
          }
        }
      }

      a
    })
    .collect::<Vec<_>>()
}

impl<E: Engine> CommitmentEngineTrait<E> for CommitmentEngine<E>
where
  E::GE: PairingGroup,
{
  type Commitment = Commitment<E>;
  type CommitmentKey = CommitmentKey<E>;
  type DerandKey = DerandKey<E>;

  /// Generate a commitment key with a random tau value.
  ///
  /// # Availability
  ///
  /// This method is only available in test builds or when the `test-utils` feature is enabled.
  /// In production builds, this will return an error.
  ///
  /// # Security Warning
  ///
  /// This method generates an **insecure** commitment key using a random tau.
  /// The security of HyperKZG relies on no one knowing the secret tau value.
  ///
  /// **For production use**, call [`PublicParams::setup_with_ptau_dir`] or
  /// [`R1CSShape::commitment_key_from_ptau_dir`] to load commitment keys from
  /// Powers of Tau ceremony files (e.g., from the Ethereum PPOT ceremony).
  ///
  /// # For downstream crates
  ///
  /// If you need access to this method in your tests, add `nova-snark` with the
  /// `test-utils` feature to your `dev-dependencies`:
  ///
  /// ```toml
  /// [dev-dependencies]
  /// nova-snark = { version = "...", features = ["test-utils"] }
  /// ```
  #[cfg(any(test, feature = "test-utils"))]
  fn setup(label: &'static [u8], n: usize) -> Result<Self::CommitmentKey, NovaError> {
    Ok(Self::CommitmentKey::setup_from_rng(label, n, OsRng))
  }

  #[cfg(not(any(test, feature = "test-utils")))]
  fn setup(_label: &'static [u8], _n: usize) -> Result<Self::CommitmentKey, NovaError> {
    Err(NovaError::SetupError(
      "HyperKZG::setup is disabled in production builds. \
       Use PublicParams::setup_with_ptau_dir or R1CSShape::commitment_key_from_ptau_dir \
       with ptau files from a trusted setup ceremony. \
       For tests, enable the 'test-utils' feature."
        .to_string(),
    ))
  }

  fn derand_key(ck: &Self::CommitmentKey) -> Self::DerandKey {
    Self::DerandKey { h: ck.h }
  }

  fn commit(ck: &Self::CommitmentKey, v: &[E::Scalar], r: &E::Scalar) -> Self::Commitment {
    assert!(ck.ck.len() >= v.len());

    Commitment {
      comm: E::GE::vartime_multiscalar_mul(v, &ck.ck[..v.len()])
        + <E::GE as DlogGroup>::group(&ck.h) * r,
    }
  }

  fn batch_commit(
    ck: &Self::CommitmentKey,
    v: &[Vec<<E as Engine>::Scalar>],
    r: &[<E as Engine>::Scalar],
  ) -> Vec<Self::Commitment> {
    assert!(v.len() == r.len());

    let max = v.iter().map(|v| v.len()).max().unwrap_or(0);
    assert!(ck.ck.len() >= max);

    let h = <E::GE as DlogGroup>::group(&ck.h);

    E::GE::batch_vartime_multiscalar_mul(v, &ck.ck[..max])
      .par_iter()
      .zip(r.par_iter())
      .map(|(commit, r_i)| Commitment {
        comm: *commit + (h * r_i),
      })
      .collect()
  }

  fn commit_small<T: Integer + Into<u64> + Copy + Sync + ToPrimitive>(
    ck: &Self::CommitmentKey,
    v: &[T],
    r: &E::Scalar,
  ) -> Self::Commitment {
    assert!(ck.ck.len() >= v.len());
    Commitment {
      comm: E::GE::vartime_multiscalar_mul_small(v, &ck.ck[..v.len()])
        + <E::GE as DlogGroup>::group(&ck.h) * r,
    }
  }

  fn batch_commit_small<T: Integer + Into<u64> + Copy + Sync + ToPrimitive>(
    ck: &Self::CommitmentKey,
    v: &[Vec<T>],
    r: &[E::Scalar],
  ) -> Vec<Self::Commitment> {
    assert!(v.len() == r.len());

    let max = v.iter().map(|v| v.len()).max().unwrap_or(0);
    assert!(ck.ck.len() >= max);

    let h = <E::GE as DlogGroup>::group(&ck.h);

    E::GE::batch_vartime_multiscalar_mul_small(v, &ck.ck[..max])
      .iter()
      .zip(r.iter())
      .map(|(commit, r_i)| Commitment {
        comm: *commit + (h * r_i),
      })
      .collect()
  }

  fn derandomize(
    dk: &Self::DerandKey,
    commit: &Self::Commitment,
    r: &E::Scalar,
  ) -> Self::Commitment {
    Commitment {
      comm: commit.comm - <E::GE as DlogGroup>::group(&dk.h) * r,
    }
  }

  #[cfg(feature = "io")]
  fn load_setup(
    reader: &mut (impl std::io::Read + std::io::Seek),
    label: &'static [u8],
    n: usize,
  ) -> Result<Self::CommitmentKey, PtauFileError> {
    let num = n.next_power_of_two();

    // b = sqrt(num) so that sigma_H = [tau^b]_2 for bivariate KZG
    let b = CommitmentKey::<E>::compute_b(num);

    // read points as well as check sanity of ptau file; read b+1 G2 points to get [tau^b]_2
    let (g1_points, g2_points) = read_ptau(reader, num, b + 1)?;

    let ck = g1_points.to_vec();

    // Standard ptau: g2_points[0]=[1]_2, g2_points[1]=[tau]_2, ..., g2_points[b]=[tau^b]_2
    let tau_H = g2_points[1];
    let sigma_H = g2_points[b];

    let h = *E::GE::from_label(label, 1).first().unwrap();

    Ok(CommitmentKey {
      ck,
      h,
      tau_H,
      sigma_H,
    })
  }

  /// Save keys
  #[cfg(feature = "io")]
  fn save_setup(
    ck: &Self::CommitmentKey,
    mut writer: &mut (impl std::io::Write + std::io::Seek),
  ) -> Result<(), PtauFileError> {
    let g1_points = ck.ck.clone();
    let num = g1_points.len().next_power_of_two();
    let power = num.trailing_zeros() + 1;

    // Build b+1 G2 points: [G2_gen, tau_H, ..., sigma_H] matching the load_setup format.
    // Index 0 = G2 generator, index 1 = [tau]_2, index b = [tau^b]_2 = sigma_H.
    let b = CommitmentKey::<E>::compute_b(num);
    let g2_gen = <<E::GE as PairingGroup>::G2 as DlogGroup>::gen().affine();
    let mut g2_points = vec![g2_gen; b + 1];
    g2_points[1] = ck.tau_H;
    g2_points[b] = ck.sigma_H;

    write_ptau(&mut writer, g1_points, g2_points, power)
  }

  fn commit_small_range<T: Integer + Into<u64> + Copy + Sync + ToPrimitive>(
    ck: &Self::CommitmentKey,
    v: &[T],
    r: &<E as Engine>::Scalar,
    range: Range<usize>,
    max_num_bits: usize,
  ) -> Self::Commitment {
    let bases = &ck.ck[range.clone()];
    let scalars = &v[range];

    assert!(bases.len() == scalars.len());

    let mut res =
      E::GE::vartime_multiscalar_mul_small_with_max_num_bits(scalars, bases, max_num_bits);

    if r != &E::Scalar::ZERO {
      res += <E::GE as DlogGroup>::group(&ck.h) * r;
    }

    Commitment { comm: res }
  }

  fn ck_to_coordinates(ck: &Self::CommitmentKey) -> Vec<(E::Base, E::Base)> {
    ck.to_coordinates()
  }

  fn ck_to_group_elements(ck: &Self::CommitmentKey) -> Vec<E::GE> {
    ck.ck()
      .par_iter()
      .map(|g| {
        let ge = E::GE::group(g);
        assert!(
          ge != E::GE::zero(),
          "CommitmentKey contains a generator at infinity"
        );
        ge
      })
      .collect()
  }

  fn commit_sparse_binary(
    ck: &Self::CommitmentKey,
    non_zero_indices: &[usize],
    r: &<E as Engine>::Scalar,
  ) -> Self::Commitment {
    let comm = batch_add(&ck.ck, non_zero_indices);
    let mut comm = <E::GE as DlogGroup>::group(&comm.into());

    if r != &E::Scalar::ZERO {
      comm += <E::GE as DlogGroup>::group(&ck.h) * r;
    }

    Commitment { comm }
  }
}

/// Provides an implementation of generators for proving evaluations
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ProverKey<E: Engine> {
  _p: PhantomData<E>,
}

/// A verifier key
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VerifierKey<E: Engine>
where
  E::GE: PairingGroup,
{
  #[serde_as(as = "EvmCompatSerde")]
  pub(crate) G: G1Affine<E>,
  #[serde_as(as = "EvmCompatSerde")]
  pub(crate) H: G2Affine<E>,
  #[serde_as(as = "EvmCompatSerde")]
  pub(crate) tau_H: G2Affine<E>,
  #[serde_as(as = "EvmCompatSerde")]
  pub(crate) sigma_H: G2Affine<E>, // [tau^b]_2 for bivariate KZG verification
}

/// Bivariate KZG evaluation argument: (π1, π2) proving f(α,β) = η
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EvaluationArgument<E: Engine>
where
  E::GE: PairingGroup,
{
  #[serde_as(as = "EvmCompatSerde")]
  /// [q1(τ,σ)]_1: commitment to bivariate quotient q1(X,Y) = (f(X,Y) - f(α,Y)) / (X - α)
  pi1: G1Affine<E>,
  #[serde_as(as = "EvmCompatSerde")]
  /// [q2(σ)]_1: commitment to univariate quotient q2(Y) = (f(α,Y) - η) / (Y - β)
  pi2: G1Affine<E>,
}

impl<E: Engine> EvaluationArgument<E>
where
  E::GE: PairingGroup,
{
  /// Returns the π1 proof element
  pub fn pi1(&self) -> &G1Affine<E> {
    &self.pi1
  }
  /// Returns the π2 proof element
  pub fn pi2(&self) -> &G1Affine<E> {
    &self.pi2
  }
}

/// Provides an implementation of a polynomial evaluation engine using Bivariate KZG
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationEngine<E: Engine> {
  _p: PhantomData<E>,
}

impl<E> EvaluationEngineTrait<E> for EvaluationEngine<E>
where
  E: Engine<CE = CommitmentEngine<E>>,
  E::GE: PairingGroup,
{
  type EvaluationArgument = EvaluationArgument<E>;
  type ProverKey = ProverKey<E>;
  type VerifierKey = VerifierKey<E>;

  fn setup(
    ck: &<E::CE as CommitmentEngineTrait<E>>::CommitmentKey,
  ) -> Result<(Self::ProverKey, Self::VerifierKey), NovaError> {
    let pk = ProverKey {
      _p: Default::default(),
    };

    let vk = VerifierKey {
      G: E::GE::gen().affine(),
      H: <<E::GE as PairingGroup>::G2 as DlogGroup>::gen().affine(),
      tau_H: ck.tau_H,
      sigma_H: ck.sigma_H,
    };

    Ok((pk, vk))
  }

  /// Prove that f(α, β) = η using Bivariate KZG.
  ///
  /// The polynomial `hat_P` is interpreted as the coefficients of a bivariate polynomial
  /// f(X, Y) = Σ_{i,j} f_{i,j} X^i Y^j  with column-major layout: hat_P[j*b + i] = f_{i,j}.
  ///
  /// With σ = τ^b (where b = sqrt(n)), the commitment ck satisfies ck[j*b+i] = [τ^i σ^j]_1,
  /// so `CommitmentEngine::commit(ck, hat_P, 0) = [f(τ,σ)]_1` — a valid bivariate KZG commitment.
  ///
  /// `point = [α, β]` are the two evaluation coordinates.
  fn prove(
    ck: &CommitmentKey<E>,
    _pk: &Self::ProverKey,
    _transcript: &mut <E as Engine>::TE,
    _C: &Commitment<E>,
    hat_P: &[E::Scalar],
    point: &[E::Scalar],
    _eval: &E::Scalar,
  ) -> Result<Self::EvaluationArgument, NovaError> {
    if point.len() != 2 {
      return Err(NovaError::InvalidInputLength);
    }

    let alpha = point[0];
    let beta = point[1];

    let n = hat_P.len();
    // b = sqrt(n); require n to be a perfect square (i.e. ell = log2(n) must be even)
    let b = CommitmentKey::<E>::compute_b(n.next_power_of_two());
    let n_padded = b * b;

    // Pad hat_P to n_padded with zeros if needed
    let poly: Vec<E::Scalar> = if n == n_padded {
      hat_P.to_vec()
    } else {
      let mut p = hat_P.to_vec();
      p.resize(n_padded, E::Scalar::ZERO);
      p
    };

    // q1 coefficients (bivariate, column-major, padded to n_padded)
    // For each Y-column j: P_j(X) = Σ_i poly[j*b+i] X^i, divide by (X - α) → Q_j(X) + g[j]
    let mut q1 = vec![E::Scalar::ZERO; n_padded];
    let mut g = vec![E::Scalar::ZERO; b]; // g[j] = P_j(α) = f(α, Y)|_{Y^j coefficient}

    for j in 0..b {
      let p_j = &poly[j * b..(j + 1) * b];
      if b > 1 {
        // Synthetic division of P_j by (X - α) via Horner's method from the top
        let mut quot = vec![E::Scalar::ZERO; b - 1];
        quot[b - 2] = p_j[b - 1];
        for i in (0..b - 2).rev() {
          quot[i] = p_j[i + 1] + alpha * quot[i + 1];
        }
        g[j] = p_j[0] + alpha * quot[0]; // P_j(α)

        // Store Q_j in q1 at column-major positions q1[j*b + i]
        for i in 0..b - 1 {
          q1[j * b + i] = quot[i];
        }
        // q1[j*b + (b-1)] = 0 (already)
      } else {
        // b == 1: each "column" is a single constant; quotient is 0, remainder is the constant
        g[j] = p_j[0];
      }
    }

    // π1 = [q1(τ,σ)]_1 via the standard MSM (column-major SRS with σ = τ^b)
    let pi1 = E::CE::commit(ck, &q1, &E::Scalar::ZERO).comm.affine();

    // g(Y) = Σ_j g[j] Y^j = f(α, Y)
    // Compute eval = g(β) = f(α, β) via Horner's method
    let eval_computed = {
      let mut acc = E::Scalar::ZERO;
      for &gj in g.iter().rev() {
        acc = acc * beta + gj;
      }
      acc
    };

    // q2(Y) = (g(Y) - eval) / (Y - β)
    let mut g_shifted = g.clone();
    g_shifted[0] -= eval_computed;

    let mut q2 = vec![E::Scalar::ZERO; b.saturating_sub(1)];
    if b > 1 {
      q2[b - 2] = g_shifted[b - 1];
      for i in (0..b - 2).rev() {
        q2[i] = g_shifted[i + 1] + beta * q2[i + 1];
      }
    }

    // π2 = [q2(σ)]_1 = Σ_j q2[j] * [σ^j]_1 = Σ_j q2[j] * ck[j*b]
    // Build a sparse vector where position j*b holds q2[j]
    let mut q2_padded = vec![E::Scalar::ZERO; n_padded];
    for (j, &coef) in q2.iter().enumerate() {
      q2_padded[j * b] = coef;
    }
    let pi2 = E::CE::commit(ck, &q2_padded, &E::Scalar::ZERO).comm.affine();

    Ok(EvaluationArgument { pi1, pi2 })
  }

  /// Verify the bivariate KZG evaluation proof.
  ///
  /// Checks: e(C - η·G1, [1]_2) = e(π1, [τ-α]_2) + e(π2, [σ-β]_2)
  /// (additive GT notation; the GT addition corresponds to pairing multiplication)
  fn verify(
    vk: &Self::VerifierKey,
    _transcript: &mut <E as Engine>::TE,
    C: &Commitment<E>,
    point: &[E::Scalar],
    eval: &E::Scalar,
    pi: &Self::EvaluationArgument,
  ) -> Result<(), NovaError> {
    if point.len() != 2 {
      return Err(NovaError::InvalidInputLength);
    }

    let alpha = point[0];
    let beta = point[1];

    let g2_gen = <<E::GE as PairingGroup>::G2 as DlogGroup>::gen();
    let g1_gen = E::GE::group(&vk.G);
    let tau_h = <<E::GE as PairingGroup>::G2 as DlogGroup>::group(&vk.tau_H);
    let sigma_h = <<E::GE as PairingGroup>::G2 as DlogGroup>::group(&vk.sigma_H);

    // [τ - α]_2  and  [σ - β]_2
    let tau_minus_alpha = tau_h - g2_gen * alpha;
    let sigma_minus_beta = sigma_h - g2_gen * beta;

    // LHS = C - η·G1
    let lhs = C.comm - g1_gen * eval;

    let pi1_pt = E::GE::group(&pi.pi1);
    let pi2_pt = E::GE::group(&pi.pi2);

    // Check: e(lhs, G2) == e(π1, [τ-α]_2) + e(π2, [σ-β]_2)  (additive GT)
    let lhs_pairing = E::GE::pairing(&lhs, &g2_gen);
    let rhs_pairing =
      E::GE::pairing(&pi1_pt, &tau_minus_alpha) + E::GE::pairing(&pi2_pt, &sigma_minus_beta);

    if lhs_pairing != rhs_pairing {
      return Err(NovaError::ProofVerifyError {
        reason: "Bivariate KZG pairing check failed".to_string(),
      });
    }

    Ok(())
  }
}


#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    provider::{keccak::Keccak256Transcript, Bn256EngineBivariateKZG},
    traits::TranscriptEngineTrait,
  };
  use ff::Field;
  use rand_core::OsRng;
  #[cfg(feature = "io")]
  use std::{
    fs::OpenOptions,
    io::{BufReader, BufWriter},
  };

  type E = Bn256EngineBivariateKZG;
  type Fr = <E as Engine>::Scalar;

  /// Evaluate bivariate polynomial f(X,Y) = sum_{i,j} poly[j*b+i] * X^i * Y^j at (alpha, beta).
  fn bivariate_eval(poly: &[Fr], alpha: Fr, beta: Fr) -> Fr {
    let n = poly.len();
    let b = {
      let mut b = 1usize;
      while b * b < n {
        b += 1;
      }
      b
    };
    let mut result = Fr::ZERO;
    let mut beta_pow = Fr::ONE;
    for j in 0..b {
      let mut col_eval = Fr::ZERO;
      let mut alpha_pow = Fr::ONE;
      for i in 0..b {
        col_eval += poly[j * b + i] * alpha_pow;
        alpha_pow *= alpha;
      }
      result += col_eval * beta_pow;
      beta_pow *= beta;
    }
    result
  }

  #[test]
  fn test_bivariate_kzg_eval() {
    // f(X, Y) = 1 + 2*X + 3*Y + 4*X*Y  (column-major: poly[j*b+i] = f_{i,j})
    // b=2: poly[0]=f_{0,0}=1, poly[1]=f_{1,0}=2, poly[2]=f_{0,1}=3, poly[3]=f_{1,1}=4
    let n = 4;
    let ck: CommitmentKey<E> = CommitmentEngine::setup(b"test", n).unwrap();
    let (pk, vk): (ProverKey<E>, VerifierKey<E>) = EvaluationEngine::setup(&ck).unwrap();

    let poly = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)];

    let C = CommitmentEngine::commit(&ck, &poly, &Fr::ZERO);

    let test_inner = |point: Vec<Fr>, eval: Fr| -> Result<(), NovaError> {
      let mut tr = Keccak256Transcript::new(b"TestEval");
      let proof = EvaluationEngine::prove(&ck, &pk, &mut tr, &C, &poly, &point, &eval).unwrap();
      let mut tr = Keccak256Transcript::new(b"TestEval");
      EvaluationEngine::verify(&vk, &mut tr, &C, &point, &eval, &proof)
    };

    // f(0,0) = 1
    let point = vec![Fr::from(0), Fr::from(0)];
    let eval = bivariate_eval(&poly, Fr::from(0), Fr::from(0));
    assert_eq!(eval, Fr::from(1));
    assert!(test_inner(point, eval).is_ok());

    // f(1,0) = 1 + 2 = 3
    let point = vec![Fr::from(1), Fr::from(0)];
    let eval = bivariate_eval(&poly, Fr::from(1), Fr::from(0));
    assert_eq!(eval, Fr::from(3));
    assert!(test_inner(point, eval).is_ok());

    // f(0,1) = 1 + 3 = 4
    let point = vec![Fr::from(0), Fr::from(1)];
    let eval = bivariate_eval(&poly, Fr::from(0), Fr::from(1));
    assert_eq!(eval, Fr::from(4));
    assert!(test_inner(point, eval).is_ok());

    // f(1,1) = 1 + 2 + 3 + 4 = 10
    let point = vec![Fr::from(1), Fr::from(1)];
    let eval = bivariate_eval(&poly, Fr::from(1), Fr::from(1));
    assert_eq!(eval, Fr::from(10));
    assert!(test_inner(point, eval).is_ok());

    // f(2, 3) = 1 + 2*2 + 3*3 + 4*2*3 = 1 + 4 + 9 + 24 = 38
    let point = vec![Fr::from(2), Fr::from(3)];
    let eval = bivariate_eval(&poly, Fr::from(2), Fr::from(3));
    assert_eq!(eval, Fr::from(38));
    assert!(test_inner(point, eval).is_ok());

    // Test with wrong eval -> verification must fail
    let point = vec![Fr::from(2), Fr::from(3)];
    assert!(test_inner(point, Fr::from(99)).is_err());

    let point = vec![Fr::from(1), Fr::from(1)];
    assert!(test_inner(point, Fr::from(5)).is_err());
  }

  #[test]
  fn test_bivariate_kzg_small() {
    // f(X, Y) = 5 + 0*X + 7*Y + 0*X*Y  (b=2, column-major)
    let poly = vec![Fr::from(5), Fr::ZERO, Fr::from(7), Fr::ZERO];
    let n = 4;

    // f(3, 4) = 5 + 0 + 7*4 + 0 = 33
    let point = vec![Fr::from(3), Fr::from(4)];
    let eval = bivariate_eval(&poly, Fr::from(3), Fr::from(4));
    assert_eq!(eval, Fr::from(33));

    let ck: CommitmentKey<E> = CommitmentEngine::setup(b"test", n).unwrap();
    let (pk, vk) = EvaluationEngine::setup(&ck).unwrap();

    let C = CommitmentEngine::commit(&ck, &poly, &Fr::ZERO);

    let mut prover_transcript = Keccak256Transcript::new(b"TestEval");
    let proof =
      EvaluationEngine::<E>::prove(&ck, &pk, &mut prover_transcript, &C, &poly, &point, &eval)
        .unwrap();

    let mut verifier_transcript = Keccak256Transcript::new(b"TestEval");
    assert!(
      EvaluationEngine::verify(&vk, &mut verifier_transcript, &C, &point, &eval, &proof).is_ok()
    );

    // Bad proof: swap pi1 and pi2
    let mut bad_proof = proof.clone();
    let tmp = bad_proof.pi1;
    bad_proof.pi1 = bad_proof.pi2;
    bad_proof.pi2 = tmp;
    let mut verifier_transcript2 = Keccak256Transcript::new(b"TestEval");
    assert!(
      EvaluationEngine::verify(&vk, &mut verifier_transcript2, &C, &point, &eval, &bad_proof)
        .is_err()
    );
  }

  #[test]
  fn test_bivariate_kzg_large() {
    // Test with random 4x4 bivariate polynomial (n=16, b=4)
    for n in [16_usize, 64] {
      let mut rng = OsRng;
      let poly = (0..n).map(|_| Fr::random(&mut rng)).collect::<Vec<_>>();
      let alpha = Fr::random(&mut rng);
      let beta = Fr::random(&mut rng);
      let point = vec![alpha, beta];
      let eval = bivariate_eval(&poly, alpha, beta);

      let ck: CommitmentKey<E> = CommitmentEngine::setup(b"test", n).unwrap();
      let (pk, vk) = EvaluationEngine::setup(&ck).unwrap();

      let C = CommitmentEngine::commit(&ck, &poly, &Fr::ZERO);

      let mut prover_transcript = Keccak256Transcript::new(b"TestEval");
      let proof: EvaluationArgument<E> =
        EvaluationEngine::prove(&ck, &pk, &mut prover_transcript, &C, &poly, &point, &eval)
          .unwrap();

      let mut verifier_tr = Keccak256Transcript::new(b"TestEval");
      assert!(
        EvaluationEngine::verify(&vk, &mut verifier_tr, &C, &point, &eval, &proof).is_ok()
      );

      // Wrong eval -> fail
      let mut verifier_tr2 = Keccak256Transcript::new(b"TestEval");
      let wrong_eval = eval + Fr::ONE;
      assert!(
        EvaluationEngine::verify(&vk, &mut verifier_tr2, &C, &point, &wrong_eval, &proof).is_err()
      );
    }
  }

  #[test]
  fn test_key_gen() {
    let n = 128; // next power of 2 is 128
    let tau = Fr::random(OsRng);
    let powers_of_tau = CommitmentKey::<E>::compute_powers_serial(tau, n);
    let label = b"test";
    let res1 = CommitmentKey::<E>::setup_from_tau_direct(label, &powers_of_tau, tau);
    let res2 = CommitmentKey::<E>::setup_from_tau_fixed_base_exp(label, &powers_of_tau);

    assert_eq!(res1.ck.len(), res2.ck.len());
    assert_eq!(res1.h, res2.h);
    assert_eq!(res1.tau_H, res2.tau_H);
    assert_eq!(res1.sigma_H, res2.sigma_H);
    for i in 0..res1.ck.len() {
      assert_eq!(res1.ck[i], res2.ck[i]);
    }
  }

  #[cfg(feature = "io")]
  #[test]
  fn test_save_load_ck() {
    const BUFFER_SIZE: usize = 64 * 1024;
    const LABEL: &[u8] = b"test";

    let n = 4;
    let filename = "/tmp/kzg_bivariate_test.ptau";

    let ck: CommitmentKey<E> = CommitmentEngine::setup(LABEL, n).unwrap();

    let file = OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .open(filename)
      .unwrap();
    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, file);

    CommitmentEngine::save_setup(&ck, &mut writer).unwrap();

    let file = OpenOptions::new().read(true).open(filename).unwrap();

    let mut reader = BufReader::new(file);

    let read_ck = CommitmentEngine::<E>::load_setup(&mut reader, LABEL, ck.ck.len()).unwrap();

    assert_eq!(ck.ck.len(), read_ck.ck.len());
    assert_eq!(ck.h, read_ck.h);
    assert_eq!(ck.tau_H, read_ck.tau_H);
    assert_eq!(ck.sigma_H, read_ck.sigma_H);
    for i in 0..ck.ck.len() {
      assert_eq!(ck.ck[i], read_ck.ck[i]);
    }
  }

  #[cfg(feature = "io")]
  #[ignore = "only available with external ptau files"]
  #[test]
  fn test_load_ptau() {
    let filename = "/tmp/ppot_0080_13.ptau";
    let file = OpenOptions::new().read(true).open(filename).unwrap();

    let mut reader = BufReader::new(file);

    let ck = CommitmentEngine::<E>::load_setup(&mut reader, b"test", 1).unwrap();

    let mut rng = rand::thread_rng();

    let gen_g1 = ck.ck[0];
    let t_g2 = ck.tau_H;

    for _ in 0..1000 {
      let x = Fr::from(<rand::rngs::ThreadRng as rand::Rng>::gen::<u64>(&mut rng));
      let x = x * x * x * x;

      let left = halo2curves::bn256::G1::pairing(&(gen_g1 * x), &t_g2.into());
      let right = halo2curves::bn256::G1::pairing(&gen_g1.into(), &t_g2.into()) * x;

      assert_eq!(left, right);
    }
  }
}

#[cfg(test)]
mod evm_tests {
  use super::*;
  use crate::provider::Bn256EngineKZG;

  #[test]
  fn test_commitment_evm_serialization() {
    type E = Bn256EngineKZG;

    let comm = Commitment::<E>::default();
    let bytes = bincode::serde::encode_to_vec(comm, bincode::config::legacy()).unwrap();

    println!(
      "Commitment serialized length in nova-snark: {} bytes",
      bytes.len()
    );
    println!(
      "Commitment hex: {}",
      hex::encode(&bytes[..std::cmp::min(64, bytes.len())])
    );

    // Expect 64 bytes for EVM feature, else 32 bytes
    assert_eq!(
      bytes.len(),
      if cfg!(feature = "evm") { 64 } else { 32 },
      "Commitment serialization length mismatch"
    );
  }
}
