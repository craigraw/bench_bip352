/*
 * bench_libsecp_detail.c -- Per-operation breakdown of the BIP-352 pipeline
 * using libsecp256k1.
 *
 * Runs each step in isolation to identify the bottleneck.
 */

#include "common.h"
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

#define DETAIL_N 1000
#define DETAIL_WARMUP 500
#define DETAIL_PASSES 11

static double time_ns(struct timespec *t0, struct timespec *t1) {
    return (t1->tv_sec - t0->tv_sec) * 1e9 + (t1->tv_nsec - t0->tv_nsec);
}

static double bench_step(int iters, void (*func)(void *), void *ctx_data) {
    int i, pass;
    double times[DETAIL_PASSES];

    /* Warmup */
    for (i = 0; i < DETAIL_WARMUP; i++) func(ctx_data);

    /* Measurement */
    for (pass = 0; pass < DETAIL_PASSES; pass++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < iters; i++) func(ctx_data);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        times[pass] = time_ns(&t0, &t1) / iters;
    }
    qsort(times, DETAIL_PASSES, sizeof(double), cmp_double);
    return times[DETAIL_PASSES / 2];
}

/* Context structs for each step */
typedef struct {
    secp256k1_context *ctx;
    secp256k1_pubkey *tweak_pubkeys;
    secp256k1_pubkey *shared_secrets;  /* pre-tweaked for later steps */
    unsigned char (*shared_ser)[33];
    unsigned char (*hashes)[32];
    secp256k1_pubkey *output_pubkeys;
    secp256k1_pubkey *candidates;
    secp256k1_pubkey spend_pubkey;
    int idx;
} bench_ctx;

static void step_tweak_mul(void *data) {
    bench_ctx *b = (bench_ctx *)data;
    int i = b->idx % DETAIL_N;
    secp256k1_pubkey pk = b->tweak_pubkeys[i];
    secp256k1_ec_pubkey_tweak_mul(b->ctx, &pk, SCAN_KEY);
    b->idx++;
    (void)pk; /* prevent optimization */
}

static void step_serialize(void *data) {
    bench_ctx *b = (bench_ctx *)data;
    int i = b->idx % DETAIL_N;
    unsigned char ser[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(b->ctx, ser, &len,
                                  &b->shared_secrets[i], SECP256K1_EC_COMPRESSED);
    b->idx++;
    (void)ser;
}

static void step_tagged_sha256(void *data) {
    bench_ctx *b = (bench_ctx *)data;
    int i = b->idx % DETAIL_N;
    unsigned char msg[37];
    memcpy(msg, b->shared_ser[i], 33);
    memset(msg + 33, 0, 4);
    unsigned char hash[32];
    secp256k1_tagged_sha256(b->ctx, hash, "BIP0352/SharedSecret", 20, msg, 37);
    b->idx++;
    (void)hash;
}

static void step_pubkey_create(void *data) {
    bench_ctx *b = (bench_ctx *)data;
    int i = b->idx % DETAIL_N;
    secp256k1_pubkey pk;
    secp256k1_ec_pubkey_create(b->ctx, &pk, b->hashes[i]);
    b->idx++;
    (void)pk;
}

static void step_combine(void *data) {
    bench_ctx *b = (bench_ctx *)data;
    int i = b->idx % DETAIL_N;
    const secp256k1_pubkey *pks[2] = {&b->spend_pubkey, &b->output_pubkeys[i]};
    secp256k1_pubkey cand;
    secp256k1_ec_pubkey_combine(b->ctx, &cand, pks, 2);
    b->idx++;
    (void)cand;
}

static void step_serialize2(void *data) {
    bench_ctx *b = (bench_ctx *)data;
    int i = b->idx % DETAIL_N;
    unsigned char ser[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(b->ctx, ser, &len,
                                  &b->candidates[i], SECP256K1_EC_COMPRESSED);
    b->idx++;
    (void)ser;
}

static void step_full_pipeline(void *data) {
    bench_ctx *b = (bench_ctx *)data;
    int i = b->idx % DETAIL_N;
    int j;

    secp256k1_pubkey tweak_pk = b->tweak_pubkeys[i];
    secp256k1_ec_pubkey_tweak_mul(b->ctx, &tweak_pk, SCAN_KEY);

    unsigned char ser[33];
    size_t ser_len = 33;
    secp256k1_ec_pubkey_serialize(b->ctx, ser, &ser_len,
                                  &tweak_pk, SECP256K1_EC_COMPRESSED);

    unsigned char msg[37];
    memcpy(msg, ser, 33);
    memset(msg + 33, 0, 4);
    unsigned char hash[32];
    secp256k1_tagged_sha256(b->ctx, hash, "BIP0352/SharedSecret", 20, msg, 37);

    secp256k1_pubkey out_pk;
    secp256k1_ec_pubkey_create(b->ctx, &out_pk, hash);

    const secp256k1_pubkey *pks[2] = {&b->spend_pubkey, &out_pk};
    secp256k1_pubkey cand;
    secp256k1_ec_pubkey_combine(b->ctx, &cand, pks, 2);

    unsigned char cand_ser[33];
    size_t cand_len = 33;
    secp256k1_ec_pubkey_serialize(b->ctx, cand_ser, &cand_len,
                                  &cand, SECP256K1_EC_COMPRESSED);
    int64_t prefix = extract_upper_64(cand_ser + 1);
    for (j = 0; j < OUTPUT_COUNT; j++) {
        if (OUTPUT_PREFIXES[j] == prefix) break;
    }
    b->idx++;
    (void)prefix;
}

int main(void) {
    int i;
    double ns;

    printf("=== Per-Operation Breakdown: libsecp256k1 ===\n\n");

    /* Generate test data */
    printf("Generating %d tweak points...\n", DETAIL_N);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    bench_ctx bctx;
    memset(&bctx, 0, sizeof(bctx));
    bctx.ctx = ctx;

    /* Generate tweak pubkeys */
    bctx.tweak_pubkeys = (secp256k1_pubkey *)malloc(DETAIL_N * sizeof(secp256k1_pubkey));
    {
        unsigned char seed[32];
        const char *tag = "bench_bip352_seed";
        bench_sha256((const uint8_t *)tag, strlen(tag), seed);
        for (i = 0; i < DETAIL_N; i++) {
            unsigned char buf[36], scalar_bytes[32];
            memcpy(buf, seed, 32);
            buf[32] = (unsigned char)((i >> 24) & 0xff);
            buf[33] = (unsigned char)((i >> 16) & 0xff);
            buf[34] = (unsigned char)((i >> 8) & 0xff);
            buf[35] = (unsigned char)(i & 0xff);
            bench_sha256(buf, 36, scalar_bytes);
            secp256k1_ec_pubkey_create(ctx, &bctx.tweak_pubkeys[i], scalar_bytes);
        }
    }

    /* Parse spend pubkey */
    secp256k1_ec_pubkey_parse(ctx, &bctx.spend_pubkey, SPEND_PUBKEY_COMPRESSED, 33);

    /* Pre-compute intermediate results */
    bctx.shared_secrets = (secp256k1_pubkey *)malloc(DETAIL_N * sizeof(secp256k1_pubkey));
    bctx.shared_ser = (unsigned char (*)[33])malloc(DETAIL_N * 33);
    bctx.hashes = (unsigned char (*)[32])malloc(DETAIL_N * 32);
    bctx.output_pubkeys = (secp256k1_pubkey *)malloc(DETAIL_N * sizeof(secp256k1_pubkey));
    bctx.candidates = (secp256k1_pubkey *)malloc(DETAIL_N * sizeof(secp256k1_pubkey));

    for (i = 0; i < DETAIL_N; i++) {
        bctx.shared_secrets[i] = bctx.tweak_pubkeys[i];
        secp256k1_ec_pubkey_tweak_mul(ctx, &bctx.shared_secrets[i], SCAN_KEY);

        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, bctx.shared_ser[i], &len,
                                       &bctx.shared_secrets[i], SECP256K1_EC_COMPRESSED);

        unsigned char msg[37];
        memcpy(msg, bctx.shared_ser[i], 33);
        memset(msg + 33, 0, 4);
        secp256k1_tagged_sha256(ctx, bctx.hashes[i], "BIP0352/SharedSecret", 20, msg, 37);

        secp256k1_ec_pubkey_create(ctx, &bctx.output_pubkeys[i], bctx.hashes[i]);

        const secp256k1_pubkey *pks[2] = {&bctx.spend_pubkey, &bctx.output_pubkeys[i]};
        secp256k1_ec_pubkey_combine(ctx, &bctx.candidates[i], pks, 2);
    }

    printf("Done. Running per-operation benchmarks (11 passes, median)...\n\n");

    bctx.idx = 0;
    ns = bench_step(DETAIL_N, step_tweak_mul, &bctx);
    printf("  %-32s %9.2f ns\n", "k*P (tweak_mul)", ns);

    bctx.idx = 0;
    ns = bench_step(DETAIL_N, step_serialize, &bctx);
    printf("  %-32s %9.2f ns\n", "serialize_compressed (1st)", ns);

    bctx.idx = 0;
    ns = bench_step(DETAIL_N, step_tagged_sha256, &bctx);
    printf("  %-32s %9.2f ns\n", "tagged_sha256", ns);

    bctx.idx = 0;
    ns = bench_step(DETAIL_N, step_pubkey_create, &bctx);
    printf("  %-32s %9.2f ns\n", "k*G (pubkey_create)", ns);

    bctx.idx = 0;
    ns = bench_step(DETAIL_N, step_combine, &bctx);
    printf("  %-32s %9.2f ns\n", "point_add (combine)", ns);

    bctx.idx = 0;
    ns = bench_step(DETAIL_N, step_serialize2, &bctx);
    printf("  %-32s %9.2f ns\n", "serialize_compressed (2nd)", ns);

    printf("\n  --- Full pipeline ---\n");
    bctx.idx = 0;
    ns = bench_step(DETAIL_N, step_full_pipeline, &bctx);
    printf("  %-32s %9.2f ns\n", "full pipeline (per row)", ns);

    free(bctx.tweak_pubkeys);
    free(bctx.shared_secrets);
    free(bctx.shared_ser);
    free(bctx.hashes);
    free(bctx.output_pubkeys);
    free(bctx.candidates);
    secp256k1_context_destroy(ctx);
    return 0;
}
