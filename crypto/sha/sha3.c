/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ضمن <string.h>
#ضمن "internal/sha3.h"
#ضمن "internal/common.h"

#إذا defined(__aarch64__) && defined(KECCAK1600_ASM)
#ضمن "arch/arm_arch.h"
#پایان_اگر

#إذا defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#ضمن "arch/s390x_arch.h"
#إذا defined(KECCAK1600_ASM)
#تعریف_کن S390_SHA3 1
#تعریف_کن S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#پایان_اگر
#پایان_اگر

فراغ SHA3_squeeze(uint64_t A[5][5], بیعلامت حرف *بیرون, size_t len, size_t r, صحيح بعدی);

فراغ ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#إذا defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    إذا (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#پایان_اگر
        memset(ctx->A, 0, حجم(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

صحيح ossl_sha3_init(KECCAK1600_CTX *ctx, بیعلامت حرف pad, size_t bitlen)
{
    size_t bsz = SHA3_BLOCKSIZE(bitlen);

    إذا (bsz <= حجم(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->بلوک_اندازه = bsz;
        ctx->md_اندازه = bitlen / 8;
        ctx->pad = pad;
        أرجع 1;
    }

    أرجع 0;
}

صحيح ossl_keccak_init(KECCAK1600_CTX *ctx, بیعلامت حرف pad, size_t bitlen, size_t mdlen)
{
    صحيح ret = ossl_sha3_init(ctx, pad, bitlen);

    إذا (ret)
        ctx->md_اندازه = mdlen / 8;
    أرجع ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
صحيح ossl_sha3_absorb(KECCAK1600_CTX *ctx, ثابت بیعلامت حرف *inp, size_t len)
{
    ثابت size_t bsz = ctx->بلوک_اندازه;
    size_t رقم, rem;

    إذا (ossl_unlikely(len == 0))
        أرجع 1;

    إذا (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        أرجع 0;

    /* Is there anything in the buffer already ? */
    إذا ((رقم = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - رقم;
        /* If the new input does not fill the buffer then just add it */
        إذا (len < rem) {
            کپی_حافظه(ctx->buf + رقم, inp, len);
            ctx->bufsz += len;
            أرجع 1;
        }
        /* otherwise fill up the buffer and absorb the buffer */
        کپی_حافظه(ctx->buf + رقم, inp, rem);
        /* Update the input pointer */
        inp += rem;
        len -= rem;
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_ABSORB;
    }
    /* Absorb the input - rem = leftover part of the input < blocksize) */
    rem = ctx->meth.absorb(ctx, inp, len);
    إذا (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    إذا (ossl_likely(rem > 0)) {
        کپی_حافظه(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    أرجع 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
صحيح ossl_sha3_final(KECCAK1600_CTX *ctx, بیعلامت حرف *بیرون, size_t outlen)
{
    صحيح ret;

    إذا (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        أرجع 0;
    إذا (outlen == 0)
        أرجع 1;

    ret = ctx->meth.final(ctx, بیرون, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    أرجع ret;
}

/* Calls a platform specific squeeze method */
صحيح ossl_sha3_squeeze(KECCAK1600_CTX *ctx, بیعلامت حرف *بیرون, size_t outlen)
{
    صحيح ret = 0;

    إذا (ctx->xof_state == XOF_STATE_FINAL)
        أرجع 0;
    ret = ctx->meth.squeeze(ctx, بیرون, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    أرجع ret;
}

/* Default version of the absorb() */
size_t ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, ثابت بیعلامت حرف *inp, size_t len)
{
    أرجع SHA3_absorb(ctx->A, inp, len, ctx->بلوک_اندازه);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
صحيح ossl_sha3_final_default(KECCAK1600_CTX *ctx, بیعلامت حرف *بیرون, size_t outlen)
{
    size_t bsz = ctx->بلوک_اندازه;
    size_t رقم = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + رقم, 0, bsz - رقم);
    ctx->buf[رقم] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (فراغ)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, بیرون, outlen, bsz, 0);
    أرجع 1;
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
صحيح ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, بیعلامت حرف *بیرون, size_t outlen)
{
    size_t bsz = ctx->بلوک_اندازه;
    size_t رقم = ctx->bufsz;
    size_t len;
    صحيح بعدی = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    إذا (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + رقم, 0, bsz - رقم);
        ctx->buf[رقم] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (فراغ)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        رقم = ctx->bufsz = 0;
        بعدی = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    إذا (رقم != 0) {
        إذا (outlen > ctx->bufsz)
            len = ctx->bufsz;
        وإلا
            len = outlen;
        کپی_حافظه(بیرون, ctx->buf + bsz - ctx->bufsz, len);
        بیرون += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    إذا (outlen == 0)
        أرجع 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    إذا (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, بیرون, len, bsz, بعدی);
        بعدی = 1;
        بیرون += len;
        outlen -= len;
    }
    إذا (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, بعدی);
        کپی_حافظه(بیرون, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    أرجع 1;
}

ساكن PROV_SHA3_روش shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#إذا defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
ساكن size_t sha3_absorb_s390x(KECCAK1600_CTX *ctx, ثابت بیعلامت حرف *inp, size_t len)
{
    size_t rem = len % ctx->بلوک_اندازه;
    بیعلامت صحيح fc;

    إذا (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    أرجع rem;
}

ساكن صحيح shake_final_s390x(KECCAK1600_CTX *ctx, بیعلامت حرف *بیرون, size_t outlen)
{
    بیعلامت صحيح fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, بیرون, outlen, fc, ctx->A);
    أرجع 1;
}

ساكن صحيح shake_squeeze_s390x(KECCAK1600_CTX *ctx, بیعلامت حرف *بیرون, size_t outlen)
{
    بیعلامت صحيح fc;
    size_t len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    إذا (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, بیرون, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->بلوک_اندازه;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        أرجع 1;
    }
    إذا (ctx->bufsz != 0) {
        len = ctx->بلوک_اندازه - ctx->bufsz;
        إذا (outlen < len)
            len = outlen;
        کپی_حافظه(بیرون, (حرف *)ctx->A + ctx->bufsz, len);
        بیرون += len;
        outlen -= len;
        ctx->bufsz += len;
        إذا (ctx->bufsz == ctx->بلوک_اندازه)
            ctx->bufsz = 0;
    }
    إذا (outlen == 0)
        أرجع 1;
    s390x_klmd(عدم, 0, بیرون, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->بلوک_اندازه;

    أرجع 1;
}

ساكن PROV_SHA3_روش shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#وإلاإذا defined(__aarch64__) && defined(KECCAK1600_ASM)

size_t SHA3_absorb_cext(uint64_t A[5][5], ثابت بیعلامت حرف *inp, size_t len,
    size_t r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
ساكن size_t sha3_absorb_arm(KECCAK1600_CTX *ctx, ثابت بیعلامت حرف *inp, size_t len)
{
    أرجع SHA3_absorb_cext(ctx->A, inp, len, ctx->بلوک_اندازه);
}

ساكن PROV_SHA3_روش shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#پایان_اگر

KECCAK1600_CTX *ossl_shake256_new(فراغ)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(حجم(*ctx));

    إذا (ctx == عدم)
        أرجع عدم;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_اندازه = اندازه_MAX;
    ctx->meth = shake_generic_meth;
#إذا defined(S390_SHA3)
    إذا (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#وإلاإذا defined(__aarch64__) && defined(KECCAK1600_ASM)
    إذا (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#پایان_اگر
    أرجع ctx;
}
