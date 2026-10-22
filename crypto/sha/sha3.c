/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#అన్తర్భావ <string.h>
#అన్తర్భావ "internal/sha3.h"
#అన్తర్భావ "internal/common.h"

#ఒకవేళ defined(__aarch64__) && defined(KECCAK1600_ASM)
#అన్తర్భావ "arch/arm_arch.h"
#అయితే_ముగింపు

#ఒకవేళ defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#అన్తర్భావ "arch/s390x_arch.h"
#ఒకవేళ defined(KECCAK1600_ASM)
#నిర్వచించు S390_SHA3 1
#నిర్వచించు S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#అయితే_ముగింపు
#అయితే_ముగింపు

శూన్య SHA3_squeeze(uint64_t A[5][5], గుర్తులేని అక్షరం *బహిర్గతం, size_t len, size_t r, పూర్ణాంకం తదుపరి);

శూన్య ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#ఒకవేళ defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    ఒకవేళ (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#అయితే_ముగింపు
        memset(ctx->A, 0, పరిమాణం(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

పూర్ణాంకం ossl_sha3_init(KECCAK1600_CTX *ctx, గుర్తులేని అక్షరం pad, size_t bitlen)
{
    size_t bsz = SHA3_BLOCKSIZE(bitlen);

    ఒకవేళ (bsz <= పరిమాణం(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->ఖండం_కొలత = bsz;
        ctx->md_కొలత = bitlen / 8;
        ctx->pad = pad;
        తిరిగి 1;
    }

    తిరిగి 0;
}

పూర్ణాంకం ossl_keccak_init(KECCAK1600_CTX *ctx, గుర్తులేని అక్షరం pad, size_t bitlen, size_t mdlen)
{
    పూర్ణాంకం ret = ossl_sha3_init(ctx, pad, bitlen);

    ఒకవేళ (ret)
        ctx->md_కొలత = mdlen / 8;
    తిరిగి ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
పూర్ణాంకం ossl_sha3_absorb(KECCAK1600_CTX *ctx, స్థిరరాశి గుర్తులేని అక్షరం *inp, size_t len)
{
    స్థిరరాశి size_t bsz = ctx->ఖండం_కొలత;
    size_t అంకె, rem;

    ఒకవేళ (ossl_unlikely(len == 0))
        తిరిగి 1;

    ఒకవేళ (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        తిరిగి 0;

    /* Is there anything in the buffer already ? */
    ఒకవేళ ((అంకె = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - అంకె;
        /* If the new input does not fill the buffer then just add it */
        ఒకవేళ (len < rem) {
            జ్ఞాపకం_నకలు(ctx->buf + అంకె, inp, len);
            ctx->bufsz += len;
            తిరిగి 1;
        }
        /* otherwise fill up the buffer and absorb the buffer */
        జ్ఞాపకం_నకలు(ctx->buf + అంకె, inp, rem);
        /* Update the input pointer */
        inp += rem;
        len -= rem;
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_ABSORB;
    }
    /* Absorb the input - rem = leftover part of the input < blocksize) */
    rem = ctx->meth.absorb(ctx, inp, len);
    ఒకవేళ (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    ఒకవేళ (ossl_likely(rem > 0)) {
        జ్ఞాపకం_నకలు(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    తిరిగి 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
పూర్ణాంకం ossl_sha3_final(KECCAK1600_CTX *ctx, గుర్తులేని అక్షరం *బహిర్గతం, size_t outlen)
{
    పూర్ణాంకం ret;

    ఒకవేళ (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        తిరిగి 0;
    ఒకవేళ (outlen == 0)
        తిరిగి 1;

    ret = ctx->meth.final(ctx, బహిర్గతం, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    తిరిగి ret;
}

/* Calls a platform specific squeeze method */
పూర్ణాంకం ossl_sha3_squeeze(KECCAK1600_CTX *ctx, గుర్తులేని అక్షరం *బహిర్గతం, size_t outlen)
{
    పూర్ణాంకం ret = 0;

    ఒకవేళ (ctx->xof_state == XOF_STATE_FINAL)
        తిరిగి 0;
    ret = ctx->meth.squeeze(ctx, బహిర్గతం, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    తిరిగి ret;
}

/* Default version of the absorb() */
size_t ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, స్థిరరాశి గుర్తులేని అక్షరం *inp, size_t len)
{
    తిరిగి SHA3_absorb(ctx->A, inp, len, ctx->ఖండం_కొలత);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
పూర్ణాంకం ossl_sha3_final_default(KECCAK1600_CTX *ctx, గుర్తులేని అక్షరం *బహిర్గతం, size_t outlen)
{
    size_t bsz = ctx->ఖండం_కొలత;
    size_t అంకె = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + అంకె, 0, bsz - అంకె);
    ctx->buf[అంకె] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (శూన్య)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, బహిర్గతం, outlen, bsz, 0);
    తిరిగి 1;
}

/*
 * This method can be called multiple times.
 * Rather than heavily modifying assembler for SHA3_squeeze(),
 * we instead just use the limitations of the existing function.
 * i.e. Only request multiples of the ctx->block_size when calling
 * SHA3_squeeze(). For output length requests smaller than the
 * ctx->block_size just request a single ctx->block_size bytes and
 * buffer the results. The next request will use the buffer first
 * to grab output bytes.
 */
పూర్ణాంకం ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, గుర్తులేని అక్షరం *బహిర్గతం, size_t outlen)
{
    size_t bsz = ctx->ఖండం_కొలత;
    size_t అంకె = ctx->bufsz;
    size_t len;
    పూర్ణాంకం తదుపరి = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    ఒకవేళ (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + అంకె, 0, bsz - అంకె);
        ctx->buf[అంకె] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (శూన్య)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        అంకె = ctx->bufsz = 0;
        తదుపరి = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    ఒకవేళ (అంకె != 0) {
        ఒకవేళ (outlen > ctx->bufsz)
            len = ctx->bufsz;
        లేకపోతే
            len = outlen;
        జ్ఞాపకం_నకలు(బహిర్గతం, ctx->buf + bsz - ctx->bufsz, len);
        బహిర్గతం += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    ఒకవేళ (outlen == 0)
        తిరిగి 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    ఒకవేళ (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, బహిర్గతం, len, bsz, తదుపరి);
        తదుపరి = 1;
        బహిర్గతం += len;
        outlen -= len;
    }
    ఒకవేళ (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, తదుపరి);
        జ్ఞాపకం_నకలు(బహిర్గతం, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    తిరిగి 1;
}

స్థిర PROV_SHA3_పద్ధతి shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#ఒకవేళ defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
స్థిర size_t sha3_absorb_s390x(KECCAK1600_CTX *ctx, స్థిరరాశి గుర్తులేని అక్షరం *inp, size_t len)
{
    size_t rem = len % ctx->ఖండం_కొలత;
    గుర్తులేని పూర్ణాంకం fc;

    ఒకవేళ (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    తిరిగి rem;
}

స్థిర పూర్ణాంకం shake_final_s390x(KECCAK1600_CTX *ctx, గుర్తులేని అక్షరం *బహిర్గతం, size_t outlen)
{
    గుర్తులేని పూర్ణాంకం fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, బహిర్గతం, outlen, fc, ctx->A);
    తిరిగి 1;
}

స్థిర పూర్ణాంకం shake_squeeze_s390x(KECCAK1600_CTX *ctx, గుర్తులేని అక్షరం *బహిర్గతం, size_t outlen)
{
    గుర్తులేని పూర్ణాంకం fc;
    size_t len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    ఒకవేళ (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, బహిర్గతం, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->ఖండం_కొలత;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        తిరిగి 1;
    }
    ఒకవేళ (ctx->bufsz != 0) {
        len = ctx->ఖండం_కొలత - ctx->bufsz;
        ఒకవేళ (outlen < len)
            len = outlen;
        జ్ఞాపకం_నకలు(బహిర్గతం, (అక్షరం *)ctx->A + ctx->bufsz, len);
        బహిర్గతం += len;
        outlen -= len;
        ctx->bufsz += len;
        ఒకవేళ (ctx->bufsz == ctx->ఖండం_కొలత)
            ctx->bufsz = 0;
    }
    ఒకవేళ (outlen == 0)
        తిరిగి 1;
    s390x_klmd(ఖాళీ, 0, బహిర్గతం, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->ఖండం_కొలత;

    తిరిగి 1;
}

స్థిర PROV_SHA3_పద్ధతి shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#లేదావేళ defined(__aarch64__) && defined(KECCAK1600_ASM)

size_t SHA3_absorb_cext(uint64_t A[5][5], స్థిరరాశి గుర్తులేని అక్షరం *inp, size_t len,
    size_t r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
స్థిర size_t sha3_absorb_arm(KECCAK1600_CTX *ctx, స్థిరరాశి గుర్తులేని అక్షరం *inp, size_t len)
{
    తిరిగి SHA3_absorb_cext(ctx->A, inp, len, ctx->ఖండం_కొలత);
}

స్థిర PROV_SHA3_పద్ధతి shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#అయితే_ముగింపు

KECCAK1600_CTX *ossl_shake256_new(శూన్య)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(పరిమాణం(*ctx));

    ఒకవేళ (ctx == ఖాళీ)
        తిరిగి ఖాళీ;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_కొలత = కొలత_MAX;
    ctx->meth = shake_generic_meth;
#ఒకవేళ defined(S390_SHA3)
    ఒకవేళ (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#లేదావేళ defined(__aarch64__) && defined(KECCAK1600_ASM)
    ఒకవేళ (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#అయితే_ముగింపు
    తిరిగి ctx;
}
