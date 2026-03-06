# BIP-352 Standalone Benchmark

Standalone benchmark comparing **libsecp256k1** and **UltrafastSecp256k1** on the BIP-352 Silent Payments scanning pipeline, isolated from DuckDB overhead.

## Purpose

The Frigate project tests two DuckDB extensions for CPU-based Silent Payments scanning: one wrapping libsecp256k1, the other wrapping UltrafastSecp256k1. This benchmark isolates pure single-threaded elliptic curve performance and identifies exactly where the time is spent.

## Pipeline

Each row of a BIP-352 scan executes this pipeline:

1. **k\*P** — Scalar multiplication of tweak point by scan private key
2. **Serialize** — Compress the shared secret to 33-byte SEC1 format
3. **Tagged SHA-256** — `SHA256(SHA256("BIP0352/SharedSecret") || SHA256("BIP0352/SharedSecret") || serialized || 0x00000000)`
4. **k\*G** — Generator multiplication by the hash scalar
5. **Point addition** — Add spend pubkey to the output point
6. **Serialize + prefix** — Compress the candidate and extract the upper 64 bits
7. **Prefix match** — Compare against a list of output prefixes

## Benchmarks

| Executable | Description |
|---|---|
| `bench_libsecp` | Full pipeline timing using libsecp256k1 (10K points, 11 passes, median) |
| `bench_ufsecp` | Full pipeline timing using UltrafastSecp256k1 (same parameters) |
| `bench_libsecp_detail` | Per-operation breakdown using libsecp256k1 (1K points per step) |
| `bench_ufsecp_detail` | Per-operation breakdown using UltrafastSecp256k1 (1K points per step) |

All benchmarks generate identical deterministic tweak points from `SHA256("bench_bip352_seed")` and use the same scan key and spend pubkey (derived from fixed tags, not from any real wallet), so results are directly comparable and validation prefixes must match.

## Building

```bash
git submodule update --init --recursive
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Compiler flag equalization

UltrafastSecp256k1's CMake injects `-O3 -march=native` via `target_compile_options`. libsecp256k1's CMake explicitly sets `-O2` with no arch flags — a deliberate choice by the libsecp256k1 maintainers, as `-O2` can produce faster code than `-O3` for their hand-tuned assembly paths. To equalize flags, the `CMakeLists.txt` upgrades libsecp256k1 to `-O3 -march=native` after `add_subdirectory`, matching UF's flags (last `-O` flag wins in GCC/Clang).

## Running

```bash
# Full pipeline benchmarks
./build/bench_libsecp
./build/bench_ufsecp

# Per-operation breakdown
./build/bench_libsecp_detail
./build/bench_ufsecp_detail
```

Both full pipeline benchmarks print a validation prefix at the end. These must match (`0xb63b4601066a6971`) to confirm both libraries are computing the same cryptographic results.

## Results

Measured on Intel Core Ultra 9 285K with equalized compiler flags (`-O3 -march=native`, `USE_ASM_X86_64=1`).

### Per-operation breakdown

| Operation | libsecp256k1 | UltrafastSecp256k1 | Ratio |
|---|---:|---:|---:|
| k\*P (scalar mul) | 20,941 ns | 16,397 ns | 1.28x faster |
| Serialize compressed (1st) | 15 ns | 8 ns | 1.8x faster |
| Tagged SHA-256 | 319 ns | 37 ns | 8.6x faster |
| k\*G (generator mul) | 9,768 ns | 4,637 ns | 2.11x faster |
| Point addition | 1,500 ns | 192 ns | 7.8x faster |
| Serialize compressed (2nd) | 14 ns | 1,094 ns | 0.01x |
| **Full pipeline** | **32,499 ns** | **22,671 ns** | **1.43x faster** |

### Key findings

- **UF wins overall**: 1.43x faster full pipeline, driven by faster k\*P (1.28x), k\*G (2.11x), tagged SHA-256 (8.6x, cached midstate), and point addition (7.8x).
- **k\*P improved**: UF's z-ratio precomputation in KPlan eliminates per-step Z normalization, and z-one normalization at end of `scalar_mul_with_plan` makes the first serialization a byte copy (8 ns).
- **Second serialization**: UF is slower on the second `to_compressed()` (1,094 ns vs 14 ns) because `Point::add()` returns Jacobian coordinates requiring a field inversion. libsecp256k1 stores normalized affine in `secp256k1_ge_storage`, making serialization a byte copy.

## Test vectors

All benchmarks use the same constants from `common.h`:

- **Scan private key**: `SHA256("bench_bip352_scan_key")` (32 bytes, big-endian)
- **Spend public key**: `pubkey(SHA256("bench_bip352_spend_key"))` (33 bytes, SEC1 compressed)
- **Tweak point generation**: `SHA256("bench_bip352_seed")` seeded, then `SHA256(seed || big_endian_32(i))` for each scalar, converted to a public key via generator multiplication
- **Output prefixes**: 3 non-matching prefixes (to ensure the full pipeline runs without early exit)

## Submodules

- `secp256k1/` — [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1)
- `UltrafastSecp256k1/` — [UltrafastSecp256k1](https://github.com/shrec/UltrafastSecp256k1)
