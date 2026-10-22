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

#अन्तर्भाव "internal/sha3.h"
#अन्तर्भाव <openssl/crypto.h>
#अन्तर्भाव <string.h>

#यदि defined(KECCAK1600_ASM)                                                               \
    && (defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)) \
    && !defined(OPENSSL_NO_ASM)

/* External assembly function declarations */
बाह्य शून्य SHA3_shake128_x4_inc_absorb_avx512vl(
    uint64_t *state,
    ध्रुव शून्य *in0, ध्रुव शून्य *in1,
    ध्रुव शून्य *in2, ध्रुव शून्य *in3,
    माप_प्रकार inlen);

बाह्य शून्य SHA3_shake256_x4_inc_absorb_avx512vl(
    uint64_t *state,
    ध्रुव शून्य *in0, ध्रुव शून्य *in1,
    ध्रुव शून्य *in2, ध्रुव शून्य *in3,
    माप_प्रकार inlen);

बाह्य शून्य SHA3_shake128_x4_inc_finalize_avx512vl(uint64_t *state);
बाह्य शून्य SHA3_shake256_x4_inc_finalize_avx512vl(uint64_t *state);

बाह्य शून्य SHA3_shake128_x4_inc_squeeze_avx512vl(
    शून्य *out0, शून्य *out1,
    शून्य *out2, शून्य *out3,
    माप_प्रकार outlen,
    uint64_t *state);

बाह्य शून्य SHA3_shake256_x4_inc_squeeze_avx512vl(
    शून्य *out0, शून्य *out1,
    शून्य *out2, शून्य *out3,
    माप_प्रकार outlen,
    uint64_t *state);

/* One-shot assembly function declarations */
बाह्य शून्य SHA3_shake128_x4_avx512vl(
    शून्य *out0, शून्य *out1,
    शून्य *out2, शून्य *out3,
    माप_प्रकार outlen,
    ध्रुव शून्य *in0, ध्रुव शून्य *in1,
    ध्रुव शून्य *in2, ध्रुव शून्य *in3,
    माप_प्रकार inlen);

बाह्य शून्य SHA3_shake256_x4_avx512vl(
    शून्य *out0, शून्य *out1,
    शून्य *out2, शून्य *out3,
    माप_प्रकार outlen,
    ध्रुव शून्य *in0, ध्रुव शून्य *in1,
    ध्रुव शून्य *in2, ध्रुव शून्य *in3,
    माप_प्रकार inlen);

/*
 * SHAKE-128 x4 Implementation
 */

शून्य ossl_sha3_shake128_x4_inc_init_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    स_रखो(ctx->A, 0, परिमाण(ctx->A));
    ctx->rate = SHA3_BLOCKSIZE(128);
    ctx->finalized = 0;
}

शून्य ossl_sha3_shake128_x4_inc_absorb_avx512vl(
    KECCAK1600_X4_AVX512VL_CTX *ctx,
    ध्रुव शून्य *in0, ध्रुव शून्य *in1,
    ध्रुव शून्य *in2, ध्रुव शून्य *in3,
    माप_प्रकार inlen)
{
    यदि (ctx->finalized) {
        /* Error: cannot absorb after finalize */
        प्रत्यागम;
    }

    SHA3_shake128_x4_inc_absorb_avx512vl(
        ctx->A, in0, in1, in2, in3, inlen);
}

शून्य ossl_sha3_shake128_x4_inc_cleanup_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    OPENSSL_cleanse(ctx, परिमाण(*ctx));
}

स्थिर शून्य ossl_sha3_shake128_x4_inc_finalize_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    यदि (ctx->finalized) {
        प्रत्यागम; /* Already finalized */
    }

    SHA3_shake128_x4_inc_finalize_avx512vl(ctx->A);
    ctx->finalized = 1;
}

शून्य ossl_sha3_shake128_x4_inc_squeeze_avx512vl(
    शून्य *out0, शून्य *out1,
    शून्य *out2, शून्य *out3,
    माप_प्रकार outlen,
    KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    यदि (!ctx->finalized) {
        /* Auto-finalize on first squeeze */
        ossl_sha3_shake128_x4_inc_finalize_avx512vl(ctx);
    }

    SHA3_shake128_x4_inc_squeeze_avx512vl(
        out0, out1, out2, out3, outlen, ctx->A);
}

/*
 * SHAKE-256 x4 Implementation
 */

शून्य ossl_sha3_shake256_x4_inc_init_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    स_रखो(ctx->A, 0, परिमाण(ctx->A));
    ctx->rate = SHA3_BLOCKSIZE(256);
    ctx->finalized = 0;
}

शून्य ossl_sha3_shake256_x4_inc_absorb_avx512vl(
    KECCAK1600_X4_AVX512VL_CTX *ctx,
    ध्रुव शून्य *in0, ध्रुव शून्य *in1,
    ध्रुव शून्य *in2, ध्रुव शून्य *in3,
    माप_प्रकार inlen)
{
    यदि (ctx->finalized) {
        /* Error: cannot absorb after finalize */
        प्रत्यागम;
    }

    SHA3_shake256_x4_inc_absorb_avx512vl(
        ctx->A, in0, in1, in2, in3, inlen);
}

शून्य ossl_sha3_shake256_x4_inc_cleanup_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    OPENSSL_cleanse(ctx, परिमाण(*ctx));
}

स्थिर शून्य ossl_sha3_shake256_x4_inc_finalize_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    यदि (ctx->finalized) {
        प्रत्यागम; /* Already finalized */
    }

    SHA3_shake256_x4_inc_finalize_avx512vl(ctx->A);
    ctx->finalized = 1;
}

शून्य ossl_sha3_shake256_x4_inc_squeeze_avx512vl(
    शून्य *out0, शून्य *out1,
    शून्य *out2, शून्य *out3,
    माप_प्रकार outlen,
    KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    यदि (!ctx->finalized) {
        /* Auto-finalize on first squeeze */
        ossl_sha3_shake256_x4_inc_finalize_avx512vl(ctx);
    }

    SHA3_shake256_x4_inc_squeeze_avx512vl(
        out0, out1, out2, out3, outlen, ctx->A);
}

/*
 * Single-call wrapper APIs
 */

शून्य ossl_sha3_shake128_x4_avx512vl(
    शून्य *out0, शून्य *out1,
    शून्य *out2, शून्य *out3,
    माप_प्रकार outlen,
    ध्रुव शून्य *in0, ध्रुव शून्य *in1,
    ध्रुव शून्य *in2, ध्रुव शून्य *in3,
    माप_प्रकार inlen)
{
    SHA3_shake128_x4_avx512vl(out0, out1, out2, out3, outlen,
        in0, in1, in2, in3, inlen);
}

शून्य ossl_sha3_shake256_x4_avx512vl(
    शून्य *out0, शून्य *out1,
    शून्य *out2, शून्य *out3,
    माप_प्रकार outlen,
    ध्रुव शून्य *in0, ध्रुव शून्य *in1,
    ध्रुव शून्य *in2, ध्रुव शून्य *in3,
    माप_प्रकार inlen)
{
    SHA3_shake256_x4_avx512vl(out0, out1, out2, out3, outlen,
        in0, in1, in2, in3, inlen);
}

#endif /* KECCAK1600_ASM && x86_64 && !OPENSSL_NO_ASM */
