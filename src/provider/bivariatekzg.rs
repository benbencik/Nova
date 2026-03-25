//! This module implements bivariate KZG used in Chopin protocol
//! The code is adapted from the implementation of hyperkzg.rs

#![allow(non_snake_case)]
#[cfg(feature = "io")]
use crate::provider::ptau::PtauFileError;
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

/// Default number of target chunks used in splitting up polynomial division in the kzg_open closure
const _DEFAULT_TARGET_CHUNKS: usize = 1 << 10;

/// KZG commitment key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentKey<E: Engine>
where
  E::GE: PairingGroup,
{
  ck: Vec<<E::GE as DlogGroup>::AffineGroupElement>,
  h: <E::GE as DlogGroup>::AffineGroupElement,
  tau_H: <<E::GE as PairingGroup>::G2 as DlogGroup>::AffineGroupElement, // needed only for the verifier key
  sigma_H: <<E::GE as PairingGroup>::G2 as DlogGroup>::AffineGroupElement, // needed only for the verifier key
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

  /// Returns a reference to the sigma_H field
  pub fn sigma_H(&self) -> &<<E::GE as PairingGroup>::G2 as DlogGroup>::AffineGroupElement {
    &self.sigma_H
  }

  /// Returns a slice of SRS: tau^0*sigma^0, tau^1*sigma^0, ..., tau^{b-1}*sigma^0
  /// used for all univariate KZG commitments
  pub(crate) fn uni_commit_key(&self, b: usize) -> &[<E::GE as DlogGroup>::AffineGroupElement] {
    &self.ck[..b]
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
  /// This generates a commitment key with independent random tau and sigma.
  /// Since the caller (or anyone with access to the RNG state) knows tau and sigma, this is insecure.
  pub fn setup_from_rng(label: &'static [u8], n: usize, mut rng: impl rand_core::RngCore) -> Self {
    use num_integer::Roots;
    const PAR_POWERS_THRESHOLD: usize = 1 << 16;

    let mut num_gens = n.next_power_of_two();
    if num_gens % 2 == 1 {
      num_gens <<= 1;
    }

    let b: usize = num_gens.sqrt();
    assert_eq!(b * b, num_gens, "num_gens must be a perfect square");

    let tau = E::Scalar::random(&mut rng);
    let sigma = E::Scalar::random(&mut rng);

    let (powers_of_tau, powers_of_sigma) = if b > PAR_POWERS_THRESHOLD {
      (Self::compute_powers_par(tau, b), Self::compute_powers_par(sigma, b))
    } else {
      (Self::compute_powers_serial(tau, b), Self::compute_powers_serial(sigma, b))
    };

    Self::setup_from_tau_sigma_direct(label, &powers_of_tau, &powers_of_sigma, tau, sigma)
  }

  /// Build key from independent powers of tau and sigma
  /// Produces ck of size b^2 with column-major layout:
  /// ck[j*b + i] = G1 * (tau^i * sigma^j)
  fn setup_from_tau_sigma_direct(
    label: &'static [u8],
    powers_of_tau: &[E::Scalar],
    powers_of_sigma: &[E::Scalar],
    tau: E::Scalar,
    sigma: E::Scalar,
  ) -> Self {
    let b = powers_of_tau.len();
    assert_eq!(b, powers_of_sigma.len());

    // Build SRS tau^i x sigma^j
    let ck: Vec<G1Affine<E>> = (0..b * b)
      .into_par_iter()
      .map(|k| {
        let i = k % b; // X index
        let j = k / b; // Y index
        (<E::GE as DlogGroup>::gen() * (powers_of_tau[i] * powers_of_sigma[j])).affine()
      })
      .collect();

    let h = *E::GE::from_label(label, 1).first().unwrap();

    let tau_H = (<<E::GE as PairingGroup>::G2 as DlogGroup>::gen() * tau).affine();
    let sigma_H = (<<E::GE as PairingGroup>::G2 as DlogGroup>::gen() * sigma).affine();

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
  #[allow(unreachable_code)]
  fn load_setup(
    _reader: &mut (impl std::io::Read + std::io::Seek),
    _label: &'static [u8],
    _n: usize,
  ) -> Result<Self::CommitmentKey, PtauFileError> {
    !unimplemented!("loading from files not needed for benches");
  }

  /// Save keys
  #[cfg(feature = "io")]
  #[allow(unreachable_code)]
  fn save_setup(
    _ck: &Self::CommitmentKey,
    mut _writer: &mut (impl std::io::Write + std::io::Seek),
  ) -> Result<(), PtauFileError> {
    !unimplemented!("saving to files not needed for benches");
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

impl<E: Engine> Default for ProverKey<E> {
  fn default() -> Self {
    Self { _p: PhantomData }
  }
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
  pub(crate) sigma_H: G2Affine<E>,
}

/// Provides an implementation of a polynomial evaluation argument
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EvaluationArgument<E: Engine>
where
  E::GE: PairingGroup,
{
  /// commitment to bivariate quotient q1(X,Y) = (f(X,Y) - f(alpha,Y)) / (X - alpha)
  #[serde_as(as = "EvmCompatSerde")]
  pi1: G1Affine<E>,
  /// commitment to univariate quotient q2(Y) = (f(alpha,Y) - f(alpha, beta)) / (Y - beta)
  #[serde_as(as = "EvmCompatSerde")]
  pi2: G1Affine<E>,
}

impl<E: Engine> EvaluationArgument<E>
where
  E::GE: PairingGroup,
{
  /// Create an evaluation argument from the two quotient commitments.
  pub fn new(pi1: G1Affine<E>, pi2: G1Affine<E>) -> Self {
    Self { pi1, pi2 }
  }

  /// returns the pi1 proof
  pub fn pi1(&self) -> &G1Affine<E> {
    &self.pi1
  }

  /// Returns the pi2 proof
  pub fn pi2(&self) -> &G1Affine<E> {
    &self.pi2
  }
}

/// Provides an implementation of a polynomial evaluation engine using bivariate KZG
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

  /// Prove evaluation of f(alpha, beta)
  /// The polynomial hat_P is interpreted as the coefficients of a bivariate polynomial
  /// f(X, Y) = Sum_{i,j} f_{i,j} X^i Y^j with hat_P[j*b + i] = f_{i,j}.
  fn prove(
    ck: &CommitmentKey<E>,
    _pk: &Self::ProverKey,
    _transcript: &mut <E as Engine>::TE,
    _C: &Commitment<E>,
    hat_P: &[E::Scalar],
    point: &[E::Scalar],
    _eval: &E::Scalar,
  ) -> Result<Self::EvaluationArgument, NovaError> {
    use num_integer::Roots;

    // bivariate kzg expects evaluation point (alpha, beta)
    if point.len() != 2 {
      return Err(NovaError::InvalidInputLength);
    }
    let alpha = point[0];
    let beta = point[1];

    let n = hat_P.len();
    let n_padded = n.next_power_of_two();
    let b = n_padded.sqrt();

    // TODO: Verify if this assumption also holds for Chopin, so far keep it
    assert_eq!(b * b, n_padded, "n must be a perfect square");

    // pad polynomial to n_padded if needed
    let f_coeffs: Vec<E::Scalar> = {
      let mut p = hat_P.to_vec();
      p.resize(n_padded, E::Scalar::ZERO);
      p
    };

    // =======================================================
    // compute q1(X, Y) = (f(X, Y) - f(alpha, Y)) / (X - alpha)
    //
    // f(X, Y) = Sum_j f_j(X) * Y^j
    // f(alpha, Y) = Sum_j f_j(alpha) * Y^j
    // where f_j(X) = Sum_i f_ij * X^i
    //
    // q1(X, Y) = Sum_j q1_j(X) * Y^j
    // where q1_j(X) = (f_j(X) - f_j(alpha)) / (X - alpha)

    // q1_j(X) has degree (b-2) since f_j(X) has degree (b-1) and we divide by (X - alpha)
    let mut q1_coeffs = vec![E::Scalar::ZERO; n_padded];
    let mut f_alpha_Y = vec![E::Scalar::ZERO; b];

    for j in 0..b {
      // extract f_j(X)
      let f_j: Vec<E::Scalar> = (0..b).map(|i| f_coeffs[j * b + i]).collect();

      f_alpha_Y[j] = eval_univariate(&f_j, alpha);
      let q1_j = divide_by_linear(&f_j, alpha);

      // store q1_j coefficients
      for (i, &coef) in q1_j.iter().enumerate() {
        q1_coeffs[j * b + i] = coef;
      }
    }

    // =======================================================
    // compute q2(Y) = (f(alpha, Y) - f(alpha, beta)) / (Y - beta)
    //
    // f(alpha, Y) is computed above
    // f(alpha, beta) = eval of f(alpha, Y) at Y = beta

    let q2 = divide_by_linear(&f_alpha_Y, beta);
    let mut q2_coeffs = vec![E::Scalar::ZERO; n_padded];
    for (j, &coef) in q2.iter().enumerate() {
      q2_coeffs[j * b] = coef;
    }

    let (pi1, pi2) = rayon::join(
      || {
        E::CE::commit(ck, &q1_coeffs, &E::Scalar::ZERO)
          .comm
          .affine()
      },
      || {
        E::CE::commit(ck, &q2_coeffs, &E::Scalar::ZERO)
          .comm
          .affine()
      },
    );

    Ok(EvaluationArgument { pi1, pi2 })
  }

  /// A method to verify evaluations of polynomials
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

    let g1_gen = E::GE::group(&vk.G);
    let g2_gen = <<E::GE as PairingGroup>::G2 as DlogGroup>::gen();

    let tau_h = <<E::GE as PairingGroup>::G2 as DlogGroup>::group(&vk.tau_H);
    let sigma_h = <<E::GE as PairingGroup>::G2 as DlogGroup>::group(&vk.sigma_H);
    let tau_minus_alpha = tau_h - g2_gen * alpha;
    let sigma_minus_beta = sigma_h - g2_gen * beta;

    let pi1_pt = E::GE::group(&pi.pi1);
    let pi2_pt = E::GE::group(&pi.pi2);

    // e(C - [eval]_1, G2) == e(pi1, [tau-alpha]_2) + e(pi2, [sigma-beta]_2)
    let lhs = C.comm - g1_gen * eval;
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

fn eval_univariate<F: Field>(poly: &[F], x: F) -> F {
  let mut acc = F::ZERO;
  for &coef in poly.iter().rev() {
    acc = acc * x + coef;
  }
  acc
}

/// Divide polynomial by term linear term and returns the quotient
/// p(X) = p_0 + p_1 X + ... + p_{n-1} X^{n-1}
/// Calculate q(X) such that p(X) - p(r) = (X - r) * q(X)
/// q(X) has degree n-2 when p(X) has degree n-1.
pub(crate) fn divide_by_linear<F: Field>(p: &[F], r: F) -> Vec<F> {
  let n: usize = p.len();

  let mut q = vec![F::ZERO; n - 1];
  q[n - 2] = p[n - 1];
  for i in (0..n - 2).rev() {
    q[i] = p[i + 1] + r * q[i + 1];
  }
  q
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    provider::{keccak::Keccak256Transcript, Bn256EngineBivariateKZG},
    traits::TranscriptEngineTrait,
  };
  use rand::SeedableRng;
  #[cfg(feature = "io")]

  type E = Bn256EngineBivariateKZG;
  type Fr = <E as Engine>::Scalar;

  fn bivariate_eval<F: Field>(poly: &[F], x: F, y: F) -> F {
    use num_integer::Roots;

    let n = poly.len();
    let b = n.sqrt();

    let mut result = F::ZERO;
    let mut y_pow = F::ONE;

    for j in 0..b {
      let mut row_eval = F::ZERO;
      let mut x_pow = F::ONE;
      for i in 0..b {
        row_eval += poly[j * b + i] * x_pow;
        x_pow *= x;
      }
      result += row_eval * y_pow;
      y_pow *= y;
    }
    result
  }

  #[test]
  fn test_eval_univariate() {
    // p(X) = 1 + 2X + 3X^2
    let poly = vec![Fr::from(1), Fr::from(2), Fr::from(3)];
    assert_eq!(eval_univariate(&poly, Fr::ZERO), Fr::from(1)); // p(0) = 1
    assert_eq!(eval_univariate(&poly, Fr::ONE), Fr::from(6)); // p(1) = 1 + 2 + 3 = 6
    assert_eq!(eval_univariate(&poly, Fr::from(2)), Fr::from(17)); // p(2) = 1 + 4 + 12 = 17
  }

  #[test]
  fn test_divide_by_linear() {
    // p(X) = 1 + 2X + 3X^2
    // p(2) = 17
    // q(X) = (3X^2 + 2X + 1 - 17) / (X - 2) = 3X + 8
    let poly = vec![Fr::from(1), Fr::from(2), Fr::from(3)];
    let q = divide_by_linear(&poly, Fr::from(2));

    assert_eq!(q[0], Fr::from(8));
    assert_eq!(q[1], Fr::from(3));
  }

  #[test]
  fn test_bivariate_setup_and_commit() {
    // n = 4 -> b = 2
    let n = 4;
    let ck: CommitmentKey<E> = CommitmentEngine::setup(b"test", n).unwrap();

    assert_eq!(ck.length(), n);

    // f(X,Y) = 1 + 2X + 3Y + 4XY
    // [f_{0,0}, f_{1,0}, f_{0,1}, f_{1,1}] = [1, 2, 3, 4]
    let poly = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)];
    let C = CommitmentEngine::commit(&ck, &poly, &Fr::ZERO);

    // Commitment should not be zero
    assert_ne!(C.comm, <E as Engine>::GE::zero());
  }

  #[test]
  fn test_bivariate_kzg_eval() {
    // f(X, Y) = 1 + 2*X + 3*Y + 4*X*Y
    let n = 4;
    let ck: CommitmentKey<E> = CommitmentEngine::setup(b"test", n).unwrap();
    let (pk, vk): (ProverKey<E>, VerifierKey<E>) = EvaluationEngine::setup(&ck).unwrap();

    let poly = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)];

    let C = CommitmentEngine::commit(&ck, &poly, &<E as Engine>::Scalar::ZERO);

    let test_inner = |point: Vec<Fr>, eval: Fr| -> Result<(), NovaError> {
      let mut tr = Keccak256Transcript::new(b"TestEval");
      let proof = EvaluationEngine::prove(&ck, &pk, &mut tr, &C, &poly, &point, &eval).unwrap();
      let mut tr = Keccak256Transcript::new(b"TestEval");
      EvaluationEngine::verify(&vk, &mut tr, &C, &point, &eval, &proof)
    };

    let point = vec![Fr::from(0), Fr::from(0)];
    let eval = Fr::ONE;
    assert!(test_inner(point, eval).is_ok());

    let point = vec![Fr::from(1), Fr::from(0)];
    let eval = Fr::from(3);
    assert!(test_inner(point, eval).is_ok());

    let point = vec![Fr::from(0), Fr::from(1)];
    let eval = Fr::from(4);
    assert!(test_inner(point, eval).is_ok());

    let point = vec![Fr::from(1), Fr::from(1)];
    let eval = Fr::from(10);
    assert!(test_inner(point, eval).is_ok());

    let point = vec![Fr::from(2), Fr::from(3)];
    let eval = Fr::from(38);
    assert!(test_inner(point, eval).is_ok());

    // Try a couple incorrect evaluations and expect failure
    let point = vec![Fr::from(2), Fr::from(3)];
    let eval = Fr::from(9);
    assert!(test_inner(point, eval).is_err());

    let point = vec![Fr::from(1), Fr::from(1)];
    let eval = Fr::from(4);
    assert!(test_inner(point, eval).is_err());
  }

  #[test]
  fn test_bivariate_kzg_small() {
    let n = 4;

    // poly = [1, 2, 1, 4]
    let poly = vec![Fr::ONE, Fr::from(2), Fr::from(1), Fr::from(4)];

    // point = [4,3]
    let point = vec![Fr::from(4), Fr::from(3)];

    // eval = 28
    let eval = Fr::from(60);

    let ck: CommitmentKey<E> = CommitmentEngine::setup(b"test", n).unwrap();
    let (pk, vk) = EvaluationEngine::setup(&ck).unwrap();

    // make a commitment
    let C = CommitmentEngine::commit(&ck, &poly, &<E as Engine>::Scalar::ZERO);

    // prove an evaluation
    let mut prover_transcript = Keccak256Transcript::new(b"TestEval");
    let proof =
      EvaluationEngine::<E>::prove(&ck, &pk, &mut prover_transcript, &C, &poly, &point, &eval)
        .unwrap();
    let post_c_p = prover_transcript.squeeze(b"c").unwrap();

    // verify the evaluation
    let mut verifier_transcript = Keccak256Transcript::new(b"TestEval");
    assert!(
      EvaluationEngine::verify(&vk, &mut verifier_transcript, &C, &point, &eval, &proof).is_ok()
    );
    let post_c_v = verifier_transcript.squeeze(b"c").unwrap();

    // check if the prover transcript and verifier transcript are kept in the same state
    assert_eq!(post_c_p, post_c_v);

    // Change the proof and expect verification to fail
    let mut bad_proof = proof.clone();
    let tmp = bad_proof.pi1;
    bad_proof.pi1 = bad_proof.pi2;
    bad_proof.pi2 = tmp;
    let mut verifier_transcript2 = Keccak256Transcript::new(b"TestEval");
    assert!(EvaluationEngine::verify(
      &vk,
      &mut verifier_transcript2,
      &C,
      &point,
      &eval,
      &bad_proof
    )
    .is_err());
  }

  #[test]
  fn test_bivariate_kzg_large() {
    // test the hyperkzg prover and verifier with random instances (derived from a seed)
    for ell in [4, 6, 8] {
      let mut rng = rand::rngs::StdRng::seed_from_u64(ell);
      let n = 1 << ell; // n = 2^ell

      let poly = (0..n).map(|_| Fr::random(&mut rng)).collect::<Vec<_>>();
      let alpha = Fr::random(&mut rng);
      let beta = Fr::random(&mut rng);
      let point = vec![alpha, beta];
      let eval = bivariate_eval(&poly, alpha, beta);

      let ck: CommitmentKey<E> = CommitmentEngine::setup(b"test", n).unwrap();
      let (pk, vk) = EvaluationEngine::setup(&ck).unwrap();

      // make a commitment
      let C = CommitmentEngine::commit(&ck, &poly, &<E as Engine>::Scalar::ZERO);

      // prove an evaluation
      let mut prover_transcript = Keccak256Transcript::new(b"TestEval");
      let proof: EvaluationArgument<E> =
        EvaluationEngine::prove(&ck, &pk, &mut prover_transcript, &C, &poly, &point, &eval)
          .unwrap();

      // verify the evaluation
      let mut verifier_tr = Keccak256Transcript::new(b"TestEval");
      assert!(EvaluationEngine::verify(&vk, &mut verifier_tr, &C, &point, &eval, &proof).is_ok());

      // Change the proof and expect verification to fail
      let mut bad_proof = proof.clone();
      let tmp = bad_proof.pi1;
      bad_proof.pi1 = bad_proof.pi2;
      bad_proof.pi2 = tmp;
      let mut verifier_tr2 = Keccak256Transcript::new(b"TestEval");
      assert!(
        EvaluationEngine::verify(&vk, &mut verifier_tr2, &C, &point, &eval, &bad_proof).is_err()
      );
    }
  }
}
