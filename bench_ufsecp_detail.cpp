/*
 * bench_ufsecp_detail.cpp -- Per-operation breakdown of the BIP-352 pipeline
 * using UltrafastSecp256k1.
 *
 * Runs each step in isolation to identify the bottleneck.
 */

#include "common.h"
#include "secp256k1/fast.hpp"
#include "secp256k1/tagged_hash.hpp"
#include "secp256k1/sha256.hpp"
#include "secp256k1/benchmark_harness.hpp"
#include "secp256k1/precompute.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <array>

using namespace secp256k1::fast;

// PointFromCompressed (same as bench_ufsecp.cpp)
static Point PointFromCompressed(const uint8_t *pub33) {
    if (pub33[0] != 0x02 && pub33[0] != 0x03) return Point::infinity();
    FieldElement x;
    if (!FieldElement::parse_bytes_strict(pub33 + 1, x)) return Point::infinity();
    auto x2 = x * x; auto x3 = x2 * x;
    auto y2 = x3 + FieldElement::from_uint64(7);
    auto t = y2;
    auto a = t.square() * t;
    auto b = a.square() * t;
    auto c = b.square().square().square() * b;
    auto d = c.square().square().square() * b;
    auto e = d.square().square() * a;
    auto f = e;
    for (int i = 0; i < 11; ++i) f = f.square();
    f = f * e;
    auto g = f;
    for (int i = 0; i < 22; ++i) g = g.square();
    g = g * f;
    auto h = g;
    for (int i = 0; i < 44; ++i) h = h.square();
    h = h * g;
    auto j = h;
    for (int i = 0; i < 88; ++i) j = j.square();
    j = j * h;
    auto k = j;
    for (int i = 0; i < 44; ++i) k = k.square();
    k = k * g;
    auto m = k.square().square().square() * b;
    auto y = m;
    for (int i = 0; i < 23; ++i) y = y.square();
    y = y * f;
    for (int i = 0; i < 6; ++i) y = y.square();
    y = y * a;
    y = y.square().square();
    if (!(y * y == y2)) return Point::infinity();
    auto y_bytes = y.to_bytes();
    bool y_is_odd = (y_bytes[31] & 1) != 0;
    bool want_odd = (pub33[0] == 0x03);
    if (y_is_odd != want_odd) y = FieldElement::from_uint64(0) - y;
    return Point::from_affine(x, y);
}

int main() {
    printf("=== Per-Operation Breakdown: UltrafastSecp256k1 ===\n\n");

    // Generate test data
    const int N = 1000;
    printf("Generating %d tweak points...\n", N);

    std::vector<std::array<uint8_t, 33>> tweak_compressed(N);
    std::vector<Point> tweak_points(N);
    {
        uint8_t seed[32];
        const char *tag = "bench_bip352_seed";
        bench_sha256(reinterpret_cast<const uint8_t*>(tag), strlen(tag), seed);
        for (int i = 0; i < N; i++) {
            uint8_t buf[36];
            memcpy(buf, seed, 32);
            buf[32] = (uint8_t)((i >> 24) & 0xff);
            buf[33] = (uint8_t)((i >> 16) & 0xff);
            buf[34] = (uint8_t)((i >> 8) & 0xff);
            buf[35] = (uint8_t)(i & 0xff);
            uint8_t scalar_bytes[32];
            bench_sha256(buf, 36, scalar_bytes);
            Scalar s = Scalar::from_bytes(scalar_bytes);
            Point p = Point::generator().scalar_mul(s);
            tweak_compressed[i] = p.to_compressed();
            tweak_points[i] = p;
        }
    }

    // Setup
    Scalar scan_scalar = Scalar::from_bytes(SCAN_KEY);
    KPlan kplan = KPlan::from_scalar(scan_scalar);
    auto tag_midstate = secp256k1::detail::make_tag_midstate("BIP0352/SharedSecret");
    Point spend_point = PointFromCompressed(SPEND_PUBKEY_COMPRESSED);

    // Pre-compute intermediate results for isolated step timing
    std::vector<Point> shared_secrets(N);
    std::vector<std::array<uint8_t, 33>> shared_compressed(N);
    std::vector<std::array<uint8_t, 32>> hashes(N);
    std::vector<Scalar> hash_scalars(N);
    std::vector<Point> output_points(N);
    std::vector<Point> candidates(N);

    for (int i = 0; i < N; i++) {
        shared_secrets[i] = tweak_points[i].scalar_mul_with_plan(kplan);
        shared_compressed[i] = shared_secrets[i].to_compressed();
        uint8_t ser[37];
        memcpy(ser, shared_compressed[i].data(), 33);
        memset(ser + 33, 0, 4);
        hashes[i] = secp256k1::detail::cached_tagged_hash(tag_midstate, ser, 37);
        hash_scalars[i] = Scalar::from_bytes(hashes[i].data());
        output_points[i] = Point::generator().scalar_mul(hash_scalars[i]);
        candidates[i] = spend_point.add(output_points[i]);
    }

    printf("Done. Running per-operation benchmarks (11 passes, median)...\n\n");

    bench::Harness H(500, 11);

    // Step 1: k*P with KPlan (the dominant operation)
    H.run_and_print("k*P (scalar_mul_with_plan)", N, [&]() {
        static int idx = 0;
        Point r = tweak_points[idx % N].scalar_mul_with_plan(kplan);
        bench::DoNotOptimize(r);
        idx++;
    });

    // Step 2: Serialize to compressed (field inversion)
    H.run_and_print("to_compressed (1st)", N, [&]() {
        static int idx = 0;
        auto c = shared_secrets[idx % N].to_compressed();
        bench::DoNotOptimize(c);
        idx++;
    });

    // Step 3: Tagged SHA-256 with cached midstate
    H.run_and_print("tagged_sha256 (cached)", N, [&]() {
        static int idx = 0;
        uint8_t ser[37];
        memcpy(ser, shared_compressed[idx % N].data(), 33);
        memset(ser + 33, 0, 4);
        auto h = secp256k1::detail::cached_tagged_hash(tag_midstate, ser, 37);
        bench::DoNotOptimize(h);
        idx++;
    });

    // Step 4: Generator multiply (k*G) - generic path
    H.run_and_print("k*G (generator.scalar_mul)", N, [&]() {
        static int idx = 0;
        Point r = Point::generator().scalar_mul(hash_scalars[idx % N]);
        bench::DoNotOptimize(r);
        idx++;
    });

    // Step 4b: Generator multiply via scalar_mul_generator (precomputed tables)
    // This requires fixed-base tables to be built
    printf("\n  --- Checking scalar_mul_generator (precomputed tables) ---\n");
    if (!fixed_base_ready()) {
        printf("  Building fixed-base tables (default config)...\n");
        FixedBaseConfig cfg;
        cfg.window_bits = 10;  // Small window to avoid huge memory
        cfg.use_cache = false;
        configure_fixed_base(cfg);
        ensure_fixed_base_ready();
    }
    H.run_and_print("k*G (scalar_mul_generator)", N, [&]() {
        static int idx = 0;
        Point r = scalar_mul_generator(hash_scalars[idx % N]);
        bench::DoNotOptimize(r);
        idx++;
    });

    // Step 5: Point addition
    H.run_and_print("point_add", N, [&]() {
        static int idx = 0;
        Point r = spend_point.add(output_points[idx % N]);
        bench::DoNotOptimize(r);
        idx++;
    });

    // Step 6: Serialize to compressed (2nd, field inversion)
    H.run_and_print("to_compressed (2nd)", N, [&]() {
        static int idx = 0;
        auto c = candidates[idx % N].to_compressed();
        bench::DoNotOptimize(c);
        idx++;
    });

    // Step 7: Extract prefix
    H.run_and_print("extract_upper_64", N, [&]() {
        static int idx = 0;
        auto c = candidates[idx % N].to_compressed();
        int64_t prefix = extract_upper_64(c.data() + 1);
        bench::DoNotOptimize(prefix);
        idx++;
    });

    // Full pipeline (for reference)
    printf("\n  --- Full pipeline ---\n");
    H.run_and_print("full pipeline (per row)", N, [&]() {
        static int idx = 0;
        int i = idx % N;
        Point shared = tweak_points[i].scalar_mul_with_plan(kplan);
        auto comp = shared.to_compressed();
        uint8_t ser[37];
        memcpy(ser, comp.data(), 33);
        memset(ser + 33, 0, 4);
        auto hash = secp256k1::detail::cached_tagged_hash(tag_midstate, ser, 37);
        Scalar hs = Scalar::from_bytes(hash.data());
        Point out = Point::generator().scalar_mul(hs);
        Point cand = spend_point.add(out);
        auto cc = cand.to_compressed();
        int64_t prefix = extract_upper_64(cc.data() + 1);
        bench::DoNotOptimize(prefix);
        idx++;
    });

    // Full pipeline with scalar_mul_generator
    H.run_and_print("full pipeline (gen_opt)", N, [&]() {
        static int idx = 0;
        int i = idx % N;
        Point shared = tweak_points[i].scalar_mul_with_plan(kplan);
        auto comp = shared.to_compressed();
        uint8_t ser[37];
        memcpy(ser, comp.data(), 33);
        memset(ser + 33, 0, 4);
        auto hash = secp256k1::detail::cached_tagged_hash(tag_midstate, ser, 37);
        Scalar hs = Scalar::from_bytes(hash.data());
        Point out = scalar_mul_generator(hs);
        Point cand = spend_point.add(out);
        auto cc = cand.to_compressed();
        int64_t prefix = extract_upper_64(cc.data() + 1);
        bench::DoNotOptimize(prefix);
        idx++;
    });

    return 0;
}
