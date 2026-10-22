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

#समावेश "internal/sha3.h"
#समावेश <openssl/crypto.h>
#समावेश <string.h>

#अगर defined(KECCAK1600_ASM)                                                               \
    && (defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)) \
    && !defined(OPENSSL_NO_ASM)

/* External assembly function declarations */
बाह्य व्योम SHA3_shake128_x4_inc_absorb_avx512vl(
    uint64_t *state,
    स्थिर व्योम *in0, स्थिर व्योम *in1,
    स्थिर व्योम *in2, स्थिर व्योम *in3,
    माप_प्रकार inlen);

बाह्य व्योम SHA3_shake256_x4_inc_absorb_avx512vl(
    uint64_t *state,
    स्थिर व्योम *in0, स्थिर व्योम *in1,
    स्थिर व्योम *in2, स्थिर व्योम *in3,
    माप_प्रकार inlen);

बाह्य व्योम SHA3_shake128_x4_inc_finalize_avx512vl(uint64_t *state);
बाह्य व्योम SHA3_shake256_x4_inc_finalize_avx512vl(uint64_t *state);

बाह्य व्योम SHA3_shake128_x4_inc_squeeze_avx512vl(
    व्योम *out0, व्योम *out1,
    व्योम *out2, व्योम *out3,
    माप_प्रकार outlen,
    uint64_t *state);

बाह्य व्योम SHA3_shake256_x4_inc_squeeze_avx512vl(
    व्योम *out0, व्योम *out1,
    व्योम *out2, व्योम *out3,
    माप_प्रकार outlen,
    uint64_t *state);

/* One-shot assembly function declarations */
बाह्य व्योम SHA3_shake128_x4_avx512vl(
    व्योम *out0, व्योम *out1,
    व्योम *out2, व्योम *out3,
    माप_प्रकार outlen,
    स्थिर व्योम *in0, स्थिर व्योम *in1,
    स्थिर व्योम *in2, स्थिर व्योम *in3,
    माप_प्रकार inlen);

बाह्य व्योम SHA3_shake256_x4_avx512vl(
    व्योम *out0, व्योम *out1,
    व्योम *out2, व्योम *out3,
    माप_प्रकार outlen,
    स्थिर व्योम *in0, स्थिर व्योम *in1,
    स्थिर व्योम *in2, स्थिर व्योम *in3,
    माप_प्रकार inlen);

/*
 * SHAKE-128 x4 Implementation
 */

व्योम ossl_sha3_shake128_x4_inc_init_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    स_रखो(ctx->A, 0, माप(ctx->A));
    ctx->rate = SHA3_BLOCKSIZE(128);
    ctx->finalized = 0;
}

व्योम ossl_sha3_shake128_x4_inc_absorb_avx512vl(
    KECCAK1600_X4_AVX512VL_CTX *ctx,
    स्थिर व्योम *in0, स्थिर व्योम *in1,
    स्थिर व्योम *in2, स्थिर व्योम *in3,
    माप_प्रकार inlen)
{
    अगर (ctx->finalized) {
        /* Error: cannot absorb after finalize */
        वापस;
    }

    SHA3_shake128_x4_inc_absorb_avx512vl(
        ctx->A, in0, in1, in2, in3, inlen);
}

व्योम ossl_sha3_shake128_x4_inc_cleanup_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    OPENSSL_cleanse(ctx, माप(*ctx));
}

अटल व्योम ossl_sha3_shake128_x4_inc_finalize_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    अगर (ctx->finalized) {
        वापस; /* Already finalized */
    }

    SHA3_shake128_x4_inc_finalize_avx512vl(ctx->A);
    ctx->finalized = 1;
}

व्योम ossl_sha3_shake128_x4_inc_squeeze_avx512vl(
    व्योम *out0, व्योम *out1,
    व्योम *out2, व्योम *out3,
    माप_प्रकार outlen,
    KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    अगर (!ctx->finalized) {
        /* Auto-finalize on first squeeze */
        ossl_sha3_shake128_x4_inc_finalize_avx512vl(ctx);
    }

    SHA3_shake128_x4_inc_squeeze_avx512vl(
        out0, out1, out2, out3, outlen, ctx->A);
}

/*
 * SHAKE-256 x4 Implementation
 */

व्योम ossl_sha3_shake256_x4_inc_init_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    स_रखो(ctx->A, 0, माप(ctx->A));
    ctx->rate = SHA3_BLOCKSIZE(256);
    ctx->finalized = 0;
}

व्योम ossl_sha3_shake256_x4_inc_absorb_avx512vl(
    KECCAK1600_X4_AVX512VL_CTX *ctx,
    स्थिर व्योम *in0, स्थिर व्योम *in1,
    स्थिर व्योम *in2, स्थिर व्योम *in3,
    माप_प्रकार inlen)
{
    अगर (ctx->finalized) {
        /* Error: cannot absorb after finalize */
        वापस;
    }

    SHA3_shake256_x4_inc_absorb_avx512vl(
        ctx->A, in0, in1, in2, in3, inlen);
}

व्योम ossl_sha3_shake256_x4_inc_cleanup_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    OPENSSL_cleanse(ctx, माप(*ctx));
}

अटल व्योम ossl_sha3_shake256_x4_inc_finalize_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    अगर (ctx->finalized) {
        वापस; /* Already finalized */
    }

    SHA3_shake256_x4_inc_finalize_avx512vl(ctx->A);
    ctx->finalized = 1;
}

व्योम ossl_sha3_shake256_x4_inc_squeeze_avx512vl(
    व्योम *out0, व्योम *out1,
    व्योम *out2, व्योम *out3,
    माप_प्रकार outlen,
    KECCAK1600_X4_AVX512VL_CTX *ctx)
{
    अगर (!ctx->finalized) {
        /* Auto-finalize on first squeeze */
        ossl_sha3_shake256_x4_inc_finalize_avx512vl(ctx);
    }

    SHA3_shake256_x4_inc_squeeze_avx512vl(
        out0, out1, out2, out3, outlen, ctx->A);
}

/*
 * Single-call wrapper APIs
 */

व्योम ossl_sha3_shake128_x4_avx512vl(
    व्योम *out0, व्योम *out1,
    व्योम *out2, व्योम *out3,
    माप_प्रकार outlen,
    स्थिर व्योम *in0, स्थिर व्योम *in1,
    स्थिर व्योम *in2, स्थिर व्योम *in3,
    माप_प्रकार inlen)
{
    SHA3_shake128_x4_avx512vl(out0, out1, out2, out3, outlen,
        in0, in1, in2, in3, inlen);
}

व्योम ossl_sha3_shake256_x4_avx512vl(
    व्योम *out0, व्योम *out1,
    व्योम *out2, व्योम *out3,
    माप_प्रकार outlen,
    स्थिर व्योम *in0, स्थिर व्योम *in1,
    स्थिर व्योम *in2, स्थिर व्योम *in3,
    माप_प्रकार inlen)
{
    SHA3_shake256_x4_avx512vl(out0, out1, out2, out3, outlen,
        in0, in1, in2, in3, inlen);
}

#पूर्ण_अगर /* KECCAK1600_ASM && x86_64 && !OPENSSL_NO_ASM */
