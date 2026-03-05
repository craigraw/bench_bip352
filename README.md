# BIP-352 Standalone Benchmark

Standalone benchmark comparing **libsecp256k1** and **UltrafastSecp256k1** on the BIP-352 Silent Payments scanning pipeline, isolated from DuckDB overhead.

## Purpose

The Frigate project tests two DuckDB extensions for CPU-based Silent Payments scanning: one wrapping libsecp256k1, the other wrapping UltrafastSecp256k1. DuckDB scalar function timings showed UltrafastSecp256k1 was ~1.76x slower, but multi-threaded execution and memory access patterns at 10M-row scale compress the true per-operation ECC performance ratio.

This benchmark isolates pure single-threaded elliptic curve performance and identifies exactly where the time is spent.

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

Measured on the same machine with equalized compiler flags (`-O3 -march=native`, `USE_ASM_X86_64=1`).

### Per-operation breakdown

| Operation | libsecp256k1 | UltrafastSecp256k1 | Ratio |
|---|---:|---:|---:|
| k\*P (scalar mul) | 19,449 ns | 77,057 ns | 3.96x |
| Serialize compressed (1st) | 15 ns | 1,190 ns | 79x |
| Tagged SHA-256 | 320 ns | 38 ns | 0.12x |
| k\*G (generator mul) | 9,907 ns | 6,435 ns | 0.65x |
| Point addition | 1,516 ns | 191 ns | 0.13x |
| Serialize compressed (2nd) | 15 ns | 1,178 ns | 79x |
| **Full pipeline** | **31,049 ns** | **87,167 ns** | **2.81x** |

### Key findings

- **k\*P dominates**: 88% of UltrafastSecp256k1's pipeline time. 3.96x slower than libsecp256k1's hand-tuned x86_64 assembly. Only fixable in the UltrafastSecp256k1 library itself.
- **Serialization asymmetry**: UF is 79x slower on `to_compressed()` because it stores Jacobian coordinates requiring a field inversion. libsecp256k1 stores normalized affine in `secp256k1_ge_storage`, making serialization a byte copy.
- **UF wins on**: tagged SHA-256 (8.4x, cached midstate), generator multiply (1.54x), and point addition (7.9x) — but these are small fractions of the total pipeline.
- **DuckDB ratio compression**: The standalone ratio is 2.81x but DuckDB scalar functions show ~1.76x. DuckDB's per-row overhead is negligible (~7 ns for a table scan vs ~2.4-4.2 µs for ECC-intensive scans). The narrower DuckDB ratio likely reflects multi-threaded execution across all cores and memory access patterns at 10M-row scale differing from the standalone's tight 10K-point loop.

## Test vectors

All benchmarks use the same constants from `common.h`:

- **Scan private key**: `SHA256("bench_bip352_scan_key")` (32 bytes, big-endian)
- **Spend public key**: `pubkey(SHA256("bench_bip352_spend_key"))` (33 bytes, SEC1 compressed)
- **Tweak point generation**: `SHA256("bench_bip352_seed")` seeded, then `SHA256(seed || big_endian_32(i))` for each scalar, converted to a public key via generator multiplication
- **Output prefixes**: 3 non-matching prefixes (to ensure the full pipeline runs without early exit)

## Submodules

- `secp256k1/` — [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1)
- `UltrafastSecp256k1/` — [UltrafastSecp256k1](https://github.com/nickmitchko/UltrafastSecp256k1)
