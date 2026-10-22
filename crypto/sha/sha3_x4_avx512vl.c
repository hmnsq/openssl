/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2026 Intel Corporation. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * SHAKE x4 multi-buffer implementation for AVX-512VL
 *
 * This file provides incremental API wrappers around the AVX-512VL
 * assembly implementations for processing 4 SHAKE instances in parallel.
 *
 * Callers should check SHA3_avx512vl_capable() before calling.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "internal/sha3.h"
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/crypto.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਜੇ defined(KECCAK1600_ASM)                                                               \
    && (defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)) \
    && !defined(OPENSSL_NO_ASM)

/* External assembly function declarations */
ਬਾਹਰੀ ਖਾਲੀ SHA3_shake128_x4_inc_absorb_avx512vl(
    uint64_t *state,
    ਅਚਲ ਖਾਲੀ *in0, ਅਚਲ ਖਾਲੀ *in1,
    ਅਚਲ ਖਾਲੀ *in2, ਅਚਲ ਖਾਲੀ *in3,
    size_t inlen);

ਬਾਹਰੀ ਖਾਲੀ SHA3_shake256_x4_inc_absorb_avx512vl(
    uint64_t *state,
    ਅਚਲ ਖਾਲੀ *in0, ਅਚਲ ਖਾਲੀ *in1,
    ਅਚਲ ਖਾਲੀ *in2, ਅਚਲ ਖਾਲੀ *in3,
    size_t inlen);

ਬਾਹਰੀ ਖਾਲੀ SHA3_shake128_x4_inc_finalize_avx512vl(uint64_t *state);
ਬਾਹਰੀ ਖਾਲੀ SHA3_shake256_x4_inc_finalize_avx512vl(uint64_t *state);

ਬਾਹਰੀ ਖਾਲੀ SHA3_shake128_x4_inc_squeeze_avx512vl(
    ਖਾਲੀ *out0, ਖਾਲੀ *out1,
    ਖਾਲੀ *out2, ਖਾਲੀ *out3,
    size_t outlen,
    uint64_t *state);

ਬਾਹਰੀ ਖਾਲੀ SHA3_shake256_x4_inc_squeeze_avx512vl(
    ਖਾਲੀ *out0, ਖਾਲੀ *out1,
    ਖਾਲੀ *out2, ਖਾਲੀ *out3,
    size_t outlen,
    uint64_t *state);

/* One-shot assembly function declarations */
ਬਾਹਰੀ ਖਾਲੀ SHA3_shake128_x4_avx512vl(
    ਖਾਲੀ *out0, ਖਾਲੀ *out1,
    ਖਾਲੀ *out2, ਖਾਲੀ *out3,
    size_t outlen,
    ਅਚਲ ਖਾਲੀ *in0, ਅਚਲ ਖਾਲੀ *in1,
    ਅਚਲ ਖਾਲੀ *in2, ਅਚਲ ਖਾਲੀ *in3,
    size_t inlen);

ਬਾਹਰੀ ਖਾਲੀ SHA3_shake256_x4_avx512vl(
    ਖਾਲੀ *out0, ਖਾਲੀ *out1,
    ਖਾਲੀ *out2, ਖਾਲੀ *out3,
    size_t outlen,
    ਅਚਲ ਖਾਲੀ *in0, ਅਚਲ ਖਾਲੀ *in1,
    ਅਚਲ ਖਾਲੀ *in2, ਅਚਲ ਖਾਲੀ *in3,
    size_t inlen);

/*
 * SHAKE-128 x4 Implementation
 */

ਖਾਲੀ ossl_sha3_shake128_x4_inc_init_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    memset(ctx->A, 0, ਆਕਾਰ(ctx->A));
    ctx->ਦਰ = SHA3_BLOCKSIZE(128);
    ctx->finalized = 0;
}

ਖਾਲੀ ossl_sha3_shake128_x4_inc_absorb_avx512vl(
    KECCAK1600_X4_AVX512VL_CTX *ctx,
    ਅਚਲ ਖਾਲੀ *in0, ਅਚਲ ਖਾਲੀ *in1,
    ਅਚਲ ਖਾਲੀ *in2, ਅਚਲ ਖਾਲੀ *in3,
    size_t inlen)
{
    ਜੇ (ctx->finalized) {
        /* Error: cannot absorb after finalize */
        ਵਾਪਸ;
    }

    SHA3_shake128_x4_inc_absorb_avx512vl(
        ctx->A, in0, in1, in2, in3, inlen);
}

ਖਾਲੀ ossl_sha3_shake128_x4_inc_cleanup_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    OPENSSL_cleanse(ctx, ਆਕਾਰ(*ctx));
}

ਸਥਿਰ ਖਾਲੀ ossl_sha3_shake128_x4_inc_finalize_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    ਜੇ (ctx->finalized) {
        ਵਾਪਸ; /* Already finalized */
    }

    SHA3_shake128_x4_inc_finalize_avx512vl(ctx->A);
    ctx->finalized = 1;
}

ਖਾਲੀ ossl_sha3_shake128_x4_inc_squeeze_avx512vl(
    ਖਾਲੀ *out0, ਖਾਲੀ *out1,
    ਖਾਲੀ *out2, ਖਾਲੀ *out3,
    size_t outlen,
    KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    ਜੇ (!ctx->finalized) {
        /* Auto-finalize on first squeeze */
        ossl_sha3_shake128_x4_inc_finalize_avx512vl(ctx);
    }

    SHA3_shake128_x4_inc_squeeze_avx512vl(
        out0, out1, out2, out3, outlen, ctx->A);
}

/*
 * SHAKE-256 x4 Implementation
 */

ਖਾਲੀ ossl_sha3_shake256_x4_inc_init_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    memset(ctx->A, 0, ਆਕਾਰ(ctx->A));
    ctx->ਦਰ = SHA3_BLOCKSIZE(256);
    ctx->finalized = 0;
}

ਖਾਲੀ ossl_sha3_shake256_x4_inc_absorb_avx512vl(
    KECCAK1600_X4_AVX512VL_CTX *ctx,
    ਅਚਲ ਖਾਲੀ *in0, ਅਚਲ ਖਾਲੀ *in1,
    ਅਚਲ ਖਾਲੀ *in2, ਅਚਲ ਖਾਲੀ *in3,
    size_t inlen)
{
    ਜੇ (ctx->finalized) {
        /* Error: cannot absorb after finalize */
        ਵਾਪਸ;
    }

    SHA3_shake256_x4_inc_absorb_avx512vl(
        ctx->A, in0, in1, in2, in3, inlen);
}

ਖਾਲੀ ossl_sha3_shake256_x4_inc_cleanup_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    OPENSSL_cleanse(ctx, ਆਕਾਰ(*ctx));
}

ਸਥਿਰ ਖਾਲੀ ossl_sha3_shake256_x4_inc_finalize_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    ਜੇ (ctx->finalized) {
        ਵਾਪਸ; /* Already finalized */
    }

    SHA3_shake256_x4_inc_finalize_avx512vl(ctx->A);
    ctx->finalized = 1;
}

ਖਾਲੀ ossl_sha3_shake256_x4_inc_squeeze_avx512vl(
    ਖਾਲੀ *out0, ਖਾਲੀ *out1,
    ਖਾਲੀ *out2, ਖਾਲੀ *out3,
    size_t outlen,
    KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    ਜੇ (!ctx->finalized) {
        /* Auto-finalize on first squeeze */
        ossl_sha3_shake256_x4_inc_finalize_avx512vl(ctx);
    }

    SHA3_shake256_x4_inc_squeeze_avx512vl(
        out0, out1, out2, out3, outlen, ctx->A);
}

/*
 * Single-call wrapper APIs
 */

ਖਾਲੀ ossl_sha3_shake128_x4_avx512vl(
    ਖਾਲੀ *out0, ਖਾਲੀ *out1,
    ਖਾਲੀ *out2, ਖਾਲੀ *out3,
    size_t outlen,
    ਅਚਲ ਖਾਲੀ *in0, ਅਚਲ ਖਾਲੀ *in1,
    ਅਚਲ ਖਾਲੀ *in2, ਅਚਲ ਖਾਲੀ *in3,
    size_t inlen)
{
    SHA3_shake128_x4_avx512vl(out0, out1, out2, out3, outlen,
        in0, in1, in2, in3, inlen);
}

ਖਾਲੀ ossl_sha3_shake256_x4_avx512vl(
    ਖਾਲੀ *out0, ਖਾਲੀ *out1,
    ਖਾਲੀ *out2, ਖਾਲੀ *out3,
    size_t outlen,
    ਅਚਲ ਖਾਲੀ *in0, ਅਚਲ ਖਾਲੀ *in1,
    ਅਚਲ ਖਾਲੀ *in2, ਅਚਲ ਖਾਲੀ *in3,
    size_t inlen)
{
    SHA3_shake256_x4_avx512vl(out0, out1, out2, out3, outlen,
        in0, in1, in2, in3, inlen);
}

#ਜੇ_ਅੰਤ /* KECCAK1600_ASM && x86_64 && !OPENSSL_NO_ASM */
