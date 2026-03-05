/*
 * bench_ufsecp.cpp -- BIP-352 scanning pipeline benchmark using UltrafastSecp256k1
 *
 * Measures the per-row BIP-352 Silent Payments scanning pipeline:
 *   1. EC scalar multiply with precomputed KPlan (k*P)
 *   2. Serialize to compressed
 *   3. Tagged SHA-256
 *   4. Generator multiply (k*G)
 *   5. EC point addition
 *   6. Serialize + extract prefix
 *   7. Compare prefix against output list
 *
 * Tweak points are pre-parsed into native Point format before timing,
 * matching the DuckDB extension behavior (Frigate passes raw affine points).
 */

#include "common.h"
#include "secp256k1/fast.hpp"
#include "secp256k1/tagged_hash.hpp"
#include "secp256k1/sha256.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <vector>
#include <array>
#include <algorithm>

using namespace secp256k1::fast;

// ============================================================================
// Point decompression -- 33-byte SEC1 compressed -> Point
// (Copied from ufsecp_extension.cpp -- UltrafastSecp256k1 doesn't expose this)
// ============================================================================
static Point PointFromCompressed(const uint8_t *pub33) {
    if (pub33[0] != 0x02 && pub33[0] != 0x03) {
        return Point::infinity();
    }

    FieldElement x;
    if (!FieldElement::parse_bytes_strict(pub33 + 1, x)) {
        return Point::infinity();
    }

    // y^2 = x^3 + 7
    auto x2 = x * x;
    auto x3 = x2 * x;
    auto y2 = x3 + FieldElement::from_uint64(7);

    // sqrt via addition chain for (p+1)/4
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

    // Verify sqrt is correct
    if (!(y * y == y2)) {
        return Point::infinity();
    }

    // Fix parity
    auto y_bytes = y.to_bytes();
    bool y_is_odd = (y_bytes[31] & 1) != 0;
    bool want_odd = (pub33[0] == 0x03);
    if (y_is_odd != want_odd) {
        y = FieldElement::from_uint64(0) - y;
    }

    return Point::from_affine(x, y);
}

int main() {
    printf("=== BIP-352 Scanning Pipeline Benchmark ===\n");
    printf("Backend: UltrafastSecp256k1\n");
    printf("N = %d tweak points per pass, %d passes (median)\n\n", BENCH_N, BENCH_PASSES);

    // ================================================================
    // Phase 1: Generate N deterministic tweak points (untimed)
    // ================================================================
    printf("Generating %d deterministic tweak points...\n", BENCH_N);

    std::vector<std::array<uint8_t, 33>> tweak_compressed(BENCH_N);
    {
        // seed = SHA-256("bench_bip352_seed") using embedded SHA-256 for cross-library consistency
        uint8_t seed[32];
        const char *tag = "bench_bip352_seed";
        bench_sha256(reinterpret_cast<const uint8_t*>(tag), strlen(tag), seed);

        for (int i = 0; i < BENCH_N; i++) {
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
        }
    }
    printf("Done.\n\n");

    // ================================================================
    // Phase 2: One-time setup (untimed)
    // ================================================================
    Scalar scan_scalar = Scalar::from_bytes(SCAN_KEY);
    KPlan kplan = KPlan::from_scalar(scan_scalar);
    auto tag_midstate = secp256k1::detail::make_tag_midstate("BIP0352/SharedSecret");
    Point spend_point = PointFromCompressed(SPEND_PUBKEY_COMPRESSED);

    // Pre-parse all tweak points into native Point format (untimed).
    // This matches DuckDB extension behavior where Frigate passes raw affine points.
    printf("Pre-parsing tweak points...\n");
    std::vector<Point> tweak_points(BENCH_N);
    for (int i = 0; i < BENCH_N; i++) {
        tweak_points[i] = PointFromCompressed(tweak_compressed[i].data());
    }
    printf("Done.\n\n");

    // ================================================================
    // Phase 3: Timed pipeline
    // ================================================================
    auto pipeline = [&]() -> int64_t {
        int64_t last_prefix = 0;
        for (int i = 0; i < BENCH_N; i++) {
            // 1. k*P with precomputed KPlan
            Point shared = tweak_points[i].scalar_mul_with_plan(kplan);

            // 2. Serialize to compressed
            auto comp = shared.to_compressed();
            uint8_t ser[37];
            memcpy(ser, comp.data(), 33);
            memset(ser + 33, 0, 4);

            // 3. Tagged SHA-256 with cached midstate
            auto hash = secp256k1::detail::cached_tagged_hash(tag_midstate, ser, 37);

            // 4. Generator multiply
            Scalar hs = Scalar::from_bytes(hash.data());
            Point out = Point::generator().scalar_mul(hs);

            // 5. Point addition
            Point cand = spend_point.add(out);

            // 6. Serialize + extract prefix
            auto cc = cand.to_compressed();
            last_prefix = extract_upper_64(cc.data() + 1);

            // 7. Output comparison (non-matching, just to include the work)
            for (int j = 0; j < OUTPUT_COUNT; j++) {
                if (OUTPUT_PREFIXES[j] == last_prefix) break;
            }
        }
        return last_prefix;
    };

    // Warmup
    printf("Warming up (%d passes)...\n", BENCH_WARMUP);
    for (int w = 0; w < BENCH_WARMUP; w++) pipeline();

    // Measurement: BENCH_PASSES passes, report median
    printf("Measuring (%d passes of %d ops)...\n", BENCH_PASSES, BENCH_N);
    std::vector<double> times(BENCH_PASSES);
    int64_t validation_prefix = 0;

    for (int pass = 0; pass < BENCH_PASSES; pass++) {
        auto t0 = std::chrono::high_resolution_clock::now();
        int64_t result = pipeline();
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        times[pass] = ms;
        validation_prefix = result;
        printf("  pass %2d: %8.1f ms\n", pass + 1, ms);
    }

    std::sort(times.begin(), times.end());
    double median_ms = times[BENCH_PASSES / 2];
    double ns_per_op = median_ms * 1e6 / BENCH_N;

    printf("\n");
    printf("UltrafastSecp256k1: %.1f ms / %d ops = %.1f ns/op (%.1f us/op)\n",
           median_ms, BENCH_N, ns_per_op, ns_per_op / 1000.0);
    printf("  validation prefix: 0x%016lx\n", (unsigned long)validation_prefix);

    return 0;
}
