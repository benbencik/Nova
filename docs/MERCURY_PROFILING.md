# Mercury Performance Profiling Guide

This guide explains how to profile and analyze the performance of the Mercury polynomial commitment scheme implementation in Nova.

## Table of Contents

1. [Basic Timing Instrumentation](#basic-timing-instrumentation)
2. [Advanced Profiling Tools](#advanced-profiling-tools)
3. [Recommended Profiling Workflow](#recommended-profiling-workflow)
4. [Understanding Mercury's Performance Characteristics](#understanding-mercurys-performance-characteristics)

## Basic Timing Instrumentation

### Compile-Time Timing Feature

The codebase includes a compile-time feature flag `mercury-timing` that adds lightweight timing instrumentation to key sections of the Mercury implementation.

**Enable timing:**
```bash
cargo build --release --features mercury-timing
cargo run --release --features mercury-timing --example mercury_timing
```

**Output:**
The timing feature collects:
- Section name (e.g., "compute_h_poly", "prove::msm_commit_q_g")
- Duration in microseconds
- Timestamp relative to start

**Analyzing timing data:**
```bash
# Run the example and save JSON output
cargo run --release --features mercury-timing --example mercury_timing > timing.json

# Analyze with the provided Python script
python scripts/analyze_mercury_timing.py timing.json

# Generate visualizations (requires matplotlib)
python scripts/analyze_mercury_timing.py timing.json --plot
```

## Advanced Profiling Tools

For deeper performance analysis, we recommend the following tools:

### 1. **Flamegraph (Recommended for CPU profiling)**

Flamegraphs provide excellent visualization of where CPU time is spent in the call stack.

**Why Flamegraph?**
- Visual representation of call stacks
- Easy to identify hot paths
- Works well with cryptographic operations
- Low overhead

**Setup and Usage:**

The project already has flamegraph support via the `pprof2` crate.

```bash
# Enable flamegraph feature (already in Cargo.toml)
cargo bench --features flamegraph --bench <benchmark_name>

# Or use perf + flamegraph manually:
# 1. Install dependencies
cargo install flamegraph

# 2. Record performance data
sudo flamegraph --root -- cargo run --release --example mercury_timing

# This generates flamegraph.svg
```

**Interpreting Flamegraphs:**
- Width = time spent
- Height = call depth
- Look for wide blocks in the graph
- Expected hotspots for Mercury:
  - Multi-scalar multiplications (MSM)
  - FFT operations
  - Polynomial operations

### 2. **perf (Linux Performance Counters)**

For detailed CPU-level performance analysis on Linux.

**Installation:**
```bash
# Ubuntu/Debian
sudo apt-get install linux-tools-common linux-tools-generic

# Arch
sudo pacman -S perf
```

**Usage:**
```bash
# Record performance data
sudo perf record -g --call-graph dwarf cargo run --release --example mercury_timing

# Generate report
sudo perf report

# Or generate flamegraph from perf data
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > perf-flamegraph.svg
```

**Key metrics to watch:**
- `instructions` - total instructions executed
- `cycles` - CPU cycles
- `cache-misses` - L1/L2/L3 cache misses (important for field arithmetic)
- `branch-misses` - branch prediction failures

### 3. **Instruments (macOS)**

For macOS users, Instruments provides excellent profiling.

**Usage:**
```bash
# Build with debug symbols
cargo build --release

# Launch Instruments
instruments -t "Time Profiler" target/release/examples/mercury_timing
```

### 4. **Valgrind/Callgrind (Cache profiling)**

For analyzing cache behavior, crucial for cryptographic operations.

**Installation:**
```bash
# Ubuntu/Debian
sudo apt-get install valgrind kcachegrind

# macOS
brew install valgrind kcachegrind
```

**Usage:**
```bash
# Profile cache usage
valgrind --tool=callgrind --cache-sim=yes \
  target/release/examples/mercury_timing

# Visualize with kcachegrind
kcachegrind callgrind.out.*
```

### 5. **cargo-asm and cargo-llvm-lines**

For analyzing generated assembly and LLVM IR.

```bash
cargo install cargo-asm cargo-llvm-lines

# View assembly for a specific function
cargo asm --release nova_snark::provider::mercury::compute_h_poly

# Find code bloat
cargo llvm-lines --release | head -20
```

## Recommended Profiling Workflow

### For Initial Investigation:
1. **Run basic timing** (`--features mercury-timing`)
   - Identifies which high-level sections are slow
   - Low overhead, safe for production-like benchmarks

2. **Generate flamegraph**
   - Visual overview of CPU time distribution
   - Identifies unexpected hotspots

### For Deep Analysis:
3. **Use perf for detailed metrics**
   - Cache miss analysis
   - Branch prediction analysis
   - Memory access patterns

4. **Callgrind for cache behavior**
   - Understand L1/L2/L3 cache usage
   - Critical for field arithmetic optimization

### For Specific Optimizations:
5. **cargo-asm for assembly inspection**
   - Verify compiler optimizations
   - Check vectorization (AVX2/AVX512)
   - Analyze field operation implementations

## Understanding Mercury's Performance Characteristics

### Expected Performance Breakdown

Based on the Mercury paper and cryptographic operations involved:

**Prover (prove function):**
1. **Multi-Scalar Multiplications (MSMs)** - ~60-70% of time
   - `prove::msm_commit_q_g` - Committing to q and g polynomials
   - `prove::msm_commit_s_d` - Committing to s and d polynomials
   - `prove::msm_commit_quot_f` - Committing to quotient polynomial
   - `batch_eval::msm_commit_w` - Batch evaluation MSM
   - `batch_eval::msm_commit_w_prime` - Batch evaluation MSM

2. **FFT Operations** - ~15-25% of time
   - `make_s_polynomial::fft_forward` - Forward FFT
   - `make_s_polynomial::fft_inverse` - Inverse FFT

3. **Polynomial Operations** - ~10-15% of time
   - `divide_by_binomial` - Polynomial division
   - `compute_h_poly` - Computing h polynomial
   - `make_s_polynomial` - Inner product argument polynomial

4. **Other** - ~5% of time
   - Transcript operations
   - Field arithmetic

**Verifier (verify function):**
1. **MSM Operations** - ~40-50%
   - `verify::msm_check_f` - MSM of 3 elements
   - `verify::msm_batch_eval` - MSM of 7 elements

2. **Pairing Operations** - ~50-60%
   - `verify::pairing_check` - 2 pairing evaluations

### Mathematical Complexity

From the Mercury paper:
- **Prover:** O(n) field operations, 2n + O(√n) scalar multiplications
- **Verifier:** O(log n) field operations, O(1) scalar multiplications, 2 pairings

Where n is the size of the polynomial.

### Optimization Opportunities

1. **MSM Optimizations:**
   - Pippenger's algorithm (already used)
   - Precomputation tables
   - GPU acceleration (via blitzar feature)

2. **FFT Optimizations:**
   - Ensure AVX2/AVX512 usage (via halo2curves asm feature)
   - Radix-4 or higher FFT
   - Cache-friendly access patterns

3. **Polynomial Operations:**
   - Minimize coefficient vector allocations
   - Use parallel iterators (already used)
   - SIMD for field arithmetic

4. **Memory:**
   - Reduce allocations in hot paths
   - Pre-allocate buffers
   - Arena allocators for temporary data

## Profiling Tips

1. **Always profile in release mode:** `--release`
2. **Use representative input sizes:** Test with realistic polynomial sizes
3. **Run multiple iterations:** Account for variance
4. **Isolate sections:** Profile prove and verify separately
5. **Compare before/after:** Establish baselines before optimization
6. **Profile on target hardware:** CPU features (AVX2, etc.) affect performance

## Example Profiling Session

```bash
# 1. Basic timing
cargo run --release --features mercury-timing --example mercury_timing > timing.json
python scripts/analyze_mercury_timing.py timing.json

# 2. Generate flamegraph
cargo install flamegraph
sudo flamegraph --root -- cargo run --release --example mercury_timing
# Opens flamegraph.svg in browser

# 3. Detailed perf analysis
sudo perf record -F 99 -g -- cargo run --release --example mercury_timing
sudo perf report --stdio > perf_report.txt

# 4. Cache analysis
valgrind --tool=callgrind --cache-sim=yes target/release/examples/mercury_timing
kcachegrind callgrind.out.*
```

## Additional Resources

- [Mercury Paper](https://eprint.iacr.org/2025/385.pdf)
- [BDFG20 Batch Evaluation](https://eprint.iacr.org/2020/081.pdf)
- [Flamegraph Documentation](https://github.com/flamegraph-rs/flamegraph)
- [perf Tutorial](https://perf.wiki.kernel.org/index.php/Tutorial)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
