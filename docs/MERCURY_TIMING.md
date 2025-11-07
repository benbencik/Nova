# Mercury Timing Instrumentation

This README explains how to use the Mercury timing instrumentation feature.

## Quick Start

### 1. Build with Timing Enabled

```bash
cargo build --release --features mercury-timing
```

### 2. Run Tests with Timing

```bash
# Run a specific mercury test
cargo test --release --features mercury-timing mercury::tests::test_mercury_evaluation_engine_15

# Run all mercury tests
cargo test --release --features mercury-timing mercury::tests
```

The timing instrumentation is embedded in the mercury.rs code and will collect performance data when the feature is enabled.

### 3. View Example

```bash
cargo run --release --features mercury-timing --example mercury_timing
```

## What Gets Timed

The instrumentation captures timing for all major operations in the Mercury prover and verifier:

### Prover Operations
- **FFT Operations**: Forward and inverse FFTs in `make_s_polynomial`
- **MSM Operations**: All multi-scalar multiplications for commitments
  - `prove::msm_commit_q_g` - Committing to q and g polynomials
  - `prove::msm_commit_s_d` - Committing to s and d polynomials
  - `prove::msm_commit_quot_f` - Committing to quotient polynomial
  - `batch_eval::msm_commit_w` - Batch evaluation commitment W
  - `batch_eval::msm_commit_w_prime` - Batch evaluation commitment W'
- **Polynomial Operations**:
  - `compute_h_poly` - Computing the h polynomial
  - `make_s_polynomial` - Creating the inner product argument polynomial
  - `divide_by_binomial` - Polynomial division
- **Batch Evaluation**: `prove::batch_evaluation_arg` - Complete batch evaluation argument generation

### Verifier Operations
- **MSM Operations**:
  - `verify::msm_check_f` - MSM for checking f polynomial (3 elements)
  - `verify::msm_batch_eval` - MSM for batch evaluation check (7 elements)
- **Pairing**: `verify::pairing_check` - Two pairing evaluations

## Programmatic Access

You can access timing data programmatically in your own tests or benchmarks:

```rust
#[cfg(feature = "mercury-timing")]
use nova_snark::provider::mercury_timing;

#[test]
fn my_performance_test() {
    #[cfg(feature = "mercury-timing")]
    {
        // Initialize timing collection
        mercury_timing::init_timing();
        
        // Run your code that calls Mercury functions
        // ... your code here ...
        
        // Get timing entries
        let entries = mercury_timing::get_timing_entries();
        
        for entry in entries {
            println!("{}: {} μs", entry.section, entry.duration_us);
        }
        
        // Or get JSON output
        let json = mercury_timing::output_timing_json();
        std::fs::write("timing.json", json).unwrap();
    }
}
```

## Analyzing Timing Data

Use the provided Python script to analyze timing data:

```bash
# Save timing data to JSON (you'll need to modify tests to output JSON)
# Then analyze it:
python scripts/analyze_mercury_timing.py timing.json

# With visualization (requires matplotlib):
python scripts/analyze_mercury_timing.py timing.json --plot
```

## Performance Impact

The timing instrumentation has minimal performance impact:
- Uses `std::time::Instant` for measurements
- Only active when `mercury-timing` feature is enabled
- Zero cost when feature is disabled (compile-time eliminated)
- Thread-safe collection using `Mutex`

For production benchmarks, you may want to disable this feature to eliminate any overhead.

## Advanced Profiling

For more detailed profiling beyond basic timing, see [docs/MERCURY_PROFILING.md](../docs/MERCURY_PROFILING.md) which covers:
- Flamegraph generation
- CPU profiling with `perf`
- Cache analysis with `valgrind/callgrind`
- Assembly inspection
- Memory profiling

## Example Output

When running tests with timing enabled, you'll see sections like:

```
compute_h_poly: 45.23ms
prove::msm_commit_q_g: 234.56ms
prove::msm_commit_s_d: 198.34ms
make_s_polynomial::fft_forward: 12.45ms
make_s_polynomial::fft_inverse: 11.89ms
...
```

This helps identify performance bottlenecks in the Mercury implementation.
