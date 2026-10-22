/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#شامل <string.h>
#شامل "internal/sha3.h"
#شامل "internal/common.h"

#اگر defined(__aarch64__) && defined(KECCAK1600_ASM)
#شامل "arch/arm_arch.h"
#اگر_ختم

#اگر defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#شامل "arch/s390x_arch.h"
#اگر defined(KECCAK1600_ASM)
#تعریف_کرو S390_SHA3 1
#تعریف_کرو S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#اگر_ختم
#اگر_ختم

خالی SHA3_squeeze(uint64_t A[5][5], غیرعلامتی حرف *برآمد, size_t len, size_t r, صحیح اگلا);

خالی ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#اگر defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    اگر (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#اگر_ختم
        memset(ctx->A, 0, حجم(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

صحیح ossl_sha3_init(KECCAK1600_CTX *ctx, غیرعلامتی حرف pad, size_t bitlen)
{
    size_t bsz = SHA3_BLOCKSIZE(bitlen);

    اگر (bsz <= حجم(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->بلاک_سائز = bsz;
        ctx->md_سائز = bitlen / 8;
        ctx->pad = pad;
        واپس 1;
    }

    واپس 0;
}

صحیح ossl_keccak_init(KECCAK1600_CTX *ctx, غیرعلامتی حرف pad, size_t bitlen, size_t mdlen)
{
    صحیح ret = ossl_sha3_init(ctx, pad, bitlen);

    اگر (ret)
        ctx->md_سائز = mdlen / 8;
    واپس ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
صحیح ossl_sha3_absorb(KECCAK1600_CTX *ctx, ثابت غیرعلامتی حرف *inp, size_t len)
{
    ثابت size_t bsz = ctx->بلاک_سائز;
    size_t عدد, rem;

    اگر (ossl_unlikely(len == 0))
        واپس 1;

    اگر (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        واپس 0;

    /* Is there anything in the buffer already ? */
    اگر ((عدد = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - عدد;
        /* If the new input does not fill the buffer then just add it */
        اگر (len < rem) {
            حافظہ_نقل(ctx->buf + عدد, inp, len);
            ctx->bufsz += len;
            واپس 1;
        }
        /* otherwise fill up the buffer and absorb the buffer */
        حافظہ_نقل(ctx->buf + عدد, inp, rem);
        /* Update the input pointer */
        inp += rem;
        len -= rem;
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_ABSORB;
    }
    /* Absorb the input - rem = leftover part of the input < blocksize) */
    rem = ctx->meth.absorb(ctx, inp, len);
    اگر (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    اگر (ossl_likely(rem > 0)) {
        حافظہ_نقل(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    واپس 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
صحیح ossl_sha3_final(KECCAK1600_CTX *ctx, غیرعلامتی حرف *برآمد, size_t outlen)
{
    صحیح ret;

    اگر (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        واپس 0;
    اگر (outlen == 0)
        واپس 1;

    ret = ctx->meth.final(ctx, برآمد, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    واپس ret;
}

/* Calls a platform specific squeeze method */
صحیح ossl_sha3_squeeze(KECCAK1600_CTX *ctx, غیرعلامتی حرف *برآمد, size_t outlen)
{
    صحیح ret = 0;

    اگر (ctx->xof_state == XOF_STATE_FINAL)
        واپس 0;
    ret = ctx->meth.squeeze(ctx, برآمد, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    واپس ret;
}

/* Default version of the absorb() */
size_t ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, ثابت غیرعلامتی حرف *inp, size_t len)
{
    واپس SHA3_absorb(ctx->A, inp, len, ctx->بلاک_سائز);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
صحیح ossl_sha3_final_default(KECCAK1600_CTX *ctx, غیرعلامتی حرف *برآمد, size_t outlen)
{
    size_t bsz = ctx->بلاک_سائز;
    size_t عدد = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + عدد, 0, bsz - عدد);
    ctx->buf[عدد] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (خالی)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, برآمد, outlen, bsz, 0);
    واپس 1;
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
صحیح ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, غیرعلامتی حرف *برآمد, size_t outlen)
{
    size_t bsz = ctx->بلاک_سائز;
    size_t عدد = ctx->bufsz;
    size_t len;
    صحیح اگلا = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    اگر (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + عدد, 0, bsz - عدد);
        ctx->buf[عدد] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (خالی)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        عدد = ctx->bufsz = 0;
        اگلا = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    اگر (عدد != 0) {
        اگر (outlen > ctx->bufsz)
            len = ctx->bufsz;
        ورنہ
            len = outlen;
        حافظہ_نقل(برآمد, ctx->buf + bsz - ctx->bufsz, len);
        برآمد += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    اگر (outlen == 0)
        واپس 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    اگر (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, برآمد, len, bsz, اگلا);
        اگلا = 1;
        برآمد += len;
        outlen -= len;
    }
    اگر (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, اگلا);
        حافظہ_نقل(برآمد, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    واپس 1;
}

ساکن PROV_SHA3_طریقہ shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#اگر defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
ساکن size_t sha3_absorb_s390x(KECCAK1600_CTX *ctx, ثابت غیرعلامتی حرف *inp, size_t len)
{
    size_t rem = len % ctx->بلاک_سائز;
    غیرعلامتی صحیح fc;

    اگر (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    واپس rem;
}

ساکن صحیح shake_final_s390x(KECCAK1600_CTX *ctx, غیرعلامتی حرف *برآمد, size_t outlen)
{
    غیرعلامتی صحیح fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, برآمد, outlen, fc, ctx->A);
    واپس 1;
}

ساکن صحیح shake_squeeze_s390x(KECCAK1600_CTX *ctx, غیرعلامتی حرف *برآمد, size_t outlen)
{
    غیرعلامتی صحیح fc;
    size_t len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    اگر (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, برآمد, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->بلاک_سائز;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        واپس 1;
    }
    اگر (ctx->bufsz != 0) {
        len = ctx->بلاک_سائز - ctx->bufsz;
        اگر (outlen < len)
            len = outlen;
        حافظہ_نقل(برآمد, (حرف *)ctx->A + ctx->bufsz, len);
        برآمد += len;
        outlen -= len;
        ctx->bufsz += len;
        اگر (ctx->bufsz == ctx->بلاک_سائز)
            ctx->bufsz = 0;
    }
    اگر (outlen == 0)
        واپس 1;
    s390x_klmd(تہی, 0, برآمد, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->بلاک_سائز;

    واپس 1;
}

ساکن PROV_SHA3_طریقہ shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#وگرنہ_اگر defined(__aarch64__) && defined(KECCAK1600_ASM)

size_t SHA3_absorb_cext(uint64_t A[5][5], ثابت غیرعلامتی حرف *inp, size_t len,
    size_t r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
ساکن size_t sha3_absorb_arm(KECCAK1600_CTX *ctx, ثابت غیرعلامتی حرف *inp, size_t len)
{
    واپس SHA3_absorb_cext(ctx->A, inp, len, ctx->بلاک_سائز);
}

ساکن PROV_SHA3_طریقہ shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#اگر_ختم

KECCAK1600_CTX *ossl_shake256_new(خالی)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(حجم(*ctx));

    اگر (ctx == تہی)
        واپس تہی;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_سائز = سائز_MAX;
    ctx->meth = shake_generic_meth;
#اگر defined(S390_SHA3)
    اگر (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#وگرنہ_اگر defined(__aarch64__) && defined(KECCAK1600_ASM)
    اگر (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#اگر_ختم
    واپس ctx;
}
