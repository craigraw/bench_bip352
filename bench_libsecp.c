/*
 * bench_libsecp.c -- BIP-352 scanning pipeline benchmark using libsecp256k1
 *
 * Measures the per-row BIP-352 Silent Payments scanning pipeline:
 *   1. EC scalar multiply (k*P via tweak_mul)
 *   2. Serialize to compressed
 *   3. Tagged SHA-256
 *   4. Generator multiply (k*G via pubkey_create)
 *   5. EC point addition (pubkey_combine)
 *   6. Serialize + extract prefix
 *   7. Compare prefix against output list
 *
 * Tweak points are pre-parsed into native secp256k1_pubkey format before
 * timing, matching the DuckDB extension behavior (Frigate passes raw affine
 * points that map directly to secp256k1_pubkey's internal representation).
 */

#include "common.h"
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

static int64_t run_pipeline(secp256k1_context *ctx,
                            const secp256k1_pubkey *spend_pubkey,
                            const secp256k1_pubkey *tweak_pubkeys) {
    int64_t last_prefix = 0;
    int i, j;

    for (i = 0; i < BENCH_N; i++) {
        /* 1. k*P (tweak_mul modifies in-place, so copy first) */
        secp256k1_pubkey tweak_pk = tweak_pubkeys[i];
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tweak_pk, SCAN_KEY)) {
            continue;
        }

        /* 2. Serialize to compressed */
        unsigned char ser[33];
        size_t ser_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, ser, &ser_len,
                                      &tweak_pk, SECP256K1_EC_COMPRESSED);

        /* 3. Tagged SHA-256 */
        unsigned char data[37];
        memcpy(data, ser, 33);
        memset(data + 33, 0, 4);
        unsigned char hash[32];
        secp256k1_tagged_sha256(ctx, hash,
                                "BIP0352/SharedSecret", 20,
                                data, 37);

        /* 4. Generator multiply */
        secp256k1_pubkey out_pk;
        if (!secp256k1_ec_pubkey_create(ctx, &out_pk, hash)) {
            continue;
        }

        /* 5. Point addition */
        const secp256k1_pubkey *pks[2] = {spend_pubkey, &out_pk};
        secp256k1_pubkey cand;
        secp256k1_ec_pubkey_combine(ctx, &cand, pks, 2);

        /* 6. Serialize + extract prefix */
        unsigned char cand_ser[33];
        size_t cand_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, cand_ser, &cand_len,
                                      &cand, SECP256K1_EC_COMPRESSED);
        last_prefix = extract_upper_64(cand_ser + 1);

        /* 7. Output comparison (non-matching, just to include the work) */
        for (j = 0; j < OUTPUT_COUNT; j++) {
            if (OUTPUT_PREFIXES[j] == last_prefix) break;
        }
    }
    return last_prefix;
}

int main(void) {
    int i, pass;

    printf("=== BIP-352 Scanning Pipeline Benchmark ===\n");
    printf("Backend: libsecp256k1\n");
    printf("N = %d tweak points per pass, %d passes (median)\n\n", BENCH_N, BENCH_PASSES);

    /* ================================================================ */
    /* Phase 1: Generate N deterministic tweak points (untimed)         */
    /* ================================================================ */
    printf("Generating %d deterministic tweak points...\n", BENCH_N);

    unsigned char (*tweak_compressed)[33] = (unsigned char (*)[33])malloc(BENCH_N * 33);
    if (!tweak_compressed) {
        fprintf(stderr, "Failed to allocate tweak points\n");
        return 1;
    }

    {
        secp256k1_context *gen_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

        /* seed = SHA-256("bench_bip352_seed") using embedded SHA-256 */
        unsigned char seed[32];
        const char *tag = "bench_bip352_seed";
        bench_sha256((const uint8_t *)tag, strlen(tag), seed);

        for (i = 0; i < BENCH_N; i++) {
            unsigned char buf[36];
            memcpy(buf, seed, 32);
            buf[32] = (unsigned char)((i >> 24) & 0xff);
            buf[33] = (unsigned char)((i >> 16) & 0xff);
            buf[34] = (unsigned char)((i >> 8) & 0xff);
            buf[35] = (unsigned char)(i & 0xff);

            unsigned char scalar_bytes[32];
            bench_sha256(buf, 36, scalar_bytes);

            secp256k1_pubkey pk;
            if (!secp256k1_ec_pubkey_create(gen_ctx, &pk, scalar_bytes)) {
                /* Extremely unlikely: scalar is zero or >= group order */
                memset(tweak_compressed[i], 0, 33);
                tweak_compressed[i][0] = 0x02; /* placeholder */
                continue;
            }
            size_t len = 33;
            secp256k1_ec_pubkey_serialize(gen_ctx, tweak_compressed[i], &len,
                                           &pk, SECP256K1_EC_COMPRESSED);
        }
        secp256k1_context_destroy(gen_ctx);
    }
    printf("Done.\n\n");

    /* ================================================================ */
    /* Phase 2: One-time setup (untimed)                                */
    /* ================================================================ */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_pubkey spend_pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &spend_pubkey, SPEND_PUBKEY_COMPRESSED, 33)) {
        fprintf(stderr, "Failed to parse spend pubkey\n");
        return 1;
    }

    /* Pre-parse all tweak points into native secp256k1_pubkey format (untimed).
     * This matches DuckDB extension behavior where Frigate passes raw affine
     * points that map directly to secp256k1_pubkey's internal representation. */
    printf("Pre-parsing tweak points...\n");
    secp256k1_pubkey *tweak_pubkeys = (secp256k1_pubkey *)malloc(BENCH_N * sizeof(secp256k1_pubkey));
    if (!tweak_pubkeys) {
        fprintf(stderr, "Failed to allocate tweak pubkeys\n");
        return 1;
    }
    for (i = 0; i < BENCH_N; i++) {
        if (!secp256k1_ec_pubkey_parse(ctx, &tweak_pubkeys[i], tweak_compressed[i], 33)) {
            fprintf(stderr, "Failed to parse tweak point %d\n", i);
            return 1;
        }
    }
    printf("Done.\n\n");

    /* ================================================================ */
    /* Phase 3: Timed pipeline                                          */
    /* ================================================================ */

    /* Warmup */
    printf("Warming up (%d passes)...\n", BENCH_WARMUP);
    for (i = 0; i < BENCH_WARMUP; i++) {
        run_pipeline(ctx, &spend_pubkey, tweak_pubkeys);
    }

    /* Measurement: BENCH_PASSES passes, report median */
    printf("Measuring (%d passes of %d ops)...\n", BENCH_PASSES, BENCH_N);
    double times[BENCH_PASSES];
    int64_t validation_prefix = 0;

    for (pass = 0; pass < BENCH_PASSES; pass++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int64_t result = run_pipeline(ctx, &spend_pubkey, tweak_pubkeys);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                    (t1.tv_nsec - t0.tv_nsec) / 1e6;
        times[pass] = ms;
        validation_prefix = result;
        printf("  pass %2d: %8.1f ms\n", pass + 1, ms);
    }

    /* Sort and take median */
    qsort(times, BENCH_PASSES, sizeof(double), cmp_double);
    double median_ms = times[BENCH_PASSES / 2];
    double ns_per_op = median_ms * 1e6 / BENCH_N;

    printf("\n");
    printf("libsecp256k1:       %.1f ms / %d ops = %.1f ns/op (%.1f us/op)\n",
           median_ms, BENCH_N, ns_per_op, ns_per_op / 1000.0);
    printf("  validation prefix: 0x%016lx\n", (unsigned long)validation_prefix);

    secp256k1_context_destroy(ctx);
    free(tweak_pubkeys);
    free(tweak_compressed);
    return 0;
}
