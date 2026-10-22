/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ "internal/sha3.h"
#ಅನ್ತರ್ಭಾವ "internal/common.h"

#ಆದರೆ defined(__aarch64__) && defined(KECCAK1600_ASM)
#ಅನ್ತರ್ಭಾವ "arch/arm_arch.h"
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#ಅನ್ತರ್ಭಾವ "arch/s390x_arch.h"
#ಆದರೆ defined(KECCAK1600_ASM)
#ವ್ಯಾಖ್ಯಾನಿಸು S390_SHA3 1
#ವ್ಯಾಖ್ಯಾನಿಸು S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ

ಶೂನ್ಯ SHA3_squeeze(uint64_t A[5][5], ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು, size_t len, size_t r, ಪೂರ್ಣಾಂಕ ಮುಂದಿನ);

ಶೂನ್ಯ ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#ಆದರೆ defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    ಆದರೆ (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#ಆದರೆ_ಅಂತ್ಯ
        memset(ctx->A, 0, ಗಾತ್ರ(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

ಪೂರ್ಣಾಂಕ ossl_sha3_init(KECCAK1600_CTX *ctx, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ pad, size_t bitlen)
{
    size_t bsz = SHA3_BLOCKSIZE(bitlen);

    ಆದರೆ (bsz <= ಗಾತ್ರ(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->ಖಂಡ_ಗಾತ್ರ = bsz;
        ctx->md_ಗಾತ್ರ = bitlen / 8;
        ctx->pad = pad;
        ಹಿಂತಿರುಗಿ 1;
    }

    ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ ossl_keccak_init(KECCAK1600_CTX *ctx, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ pad, size_t bitlen, size_t mdlen)
{
    ಪೂರ್ಣಾಂಕ ret = ossl_sha3_init(ctx, pad, bitlen);

    ಆದರೆ (ret)
        ctx->md_ಗಾತ್ರ = mdlen / 8;
    ಹಿಂತಿರುಗಿ ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
ಪೂರ್ಣಾಂಕ ossl_sha3_absorb(KECCAK1600_CTX *ctx, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *inp, size_t len)
{
    ಸ್ಥಿರಾಂಕ size_t bsz = ctx->ಖಂಡ_ಗಾತ್ರ;
    size_t ಅಂಕೆ, rem;

    ಆದರೆ (ossl_unlikely(len == 0))
        ಹಿಂತಿರುಗಿ 1;

    ಆದರೆ (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        ಹಿಂತಿರುಗಿ 0;

    /* Is there anything in the buffer already ? */
    ಆದರೆ ((ಅಂಕೆ = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - ಅಂಕೆ;
        /* If the new input does not fill the buffer then just add it */
        ಆದರೆ (len < rem) {
            ಸ್ಮರಣೆ_ನಕಲು(ctx->buf + ಅಂಕೆ, inp, len);
            ctx->bufsz += len;
            ಹಿಂತಿರುಗಿ 1;
        }
        /* otherwise fill up the buffer and absorb the buffer */
        ಸ್ಮರಣೆ_ನಕಲು(ctx->buf + ಅಂಕೆ, inp, rem);
        /* Update the input pointer */
        inp += rem;
        len -= rem;
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_ABSORB;
    }
    /* Absorb the input - rem = leftover part of the input < blocksize) */
    rem = ctx->meth.absorb(ctx, inp, len);
    ಆದರೆ (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    ಆದರೆ (ossl_likely(rem > 0)) {
        ಸ್ಮರಣೆ_ನಕಲು(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    ಹಿಂತಿರುಗಿ 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
ಪೂರ್ಣಾಂಕ ossl_sha3_final(KECCAK1600_CTX *ctx, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು, size_t outlen)
{
    ಪೂರ್ಣಾಂಕ ret;

    ಆದರೆ (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        ಹಿಂತಿರುಗಿ 0;
    ಆದರೆ (outlen == 0)
        ಹಿಂತಿರುಗಿ 1;

    ret = ctx->meth.final(ctx, ಹೊರಹೋಗು, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    ಹಿಂತಿರುಗಿ ret;
}

/* Calls a platform specific squeeze method */
ಪೂರ್ಣಾಂಕ ossl_sha3_squeeze(KECCAK1600_CTX *ctx, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು, size_t outlen)
{
    ಪೂರ್ಣಾಂಕ ret = 0;

    ಆದರೆ (ctx->xof_state == XOF_STATE_FINAL)
        ಹಿಂತಿರುಗಿ 0;
    ret = ctx->meth.squeeze(ctx, ಹೊರಹೋಗು, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    ಹಿಂತಿರುಗಿ ret;
}

/* Default version of the absorb() */
size_t ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *inp, size_t len)
{
    ಹಿಂತಿರುಗಿ SHA3_absorb(ctx->A, inp, len, ctx->ಖಂಡ_ಗಾತ್ರ);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
ಪೂರ್ಣಾಂಕ ossl_sha3_final_default(KECCAK1600_CTX *ctx, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು, size_t outlen)
{
    size_t bsz = ctx->ಖಂಡ_ಗಾತ್ರ;
    size_t ಅಂಕೆ = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + ಅಂಕೆ, 0, bsz - ಅಂಕೆ);
    ctx->buf[ಅಂಕೆ] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (ಶೂನ್ಯ)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, ಹೊರಹೋಗು, outlen, bsz, 0);
    ಹಿಂತಿರುಗಿ 1;
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
ಪೂರ್ಣಾಂಕ ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು, size_t outlen)
{
    size_t bsz = ctx->ಖಂಡ_ಗಾತ್ರ;
    size_t ಅಂಕೆ = ctx->bufsz;
    size_t len;
    ಪೂರ್ಣಾಂಕ ಮುಂದಿನ = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    ಆದರೆ (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + ಅಂಕೆ, 0, bsz - ಅಂಕೆ);
        ctx->buf[ಅಂಕೆ] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (ಶೂನ್ಯ)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        ಅಂಕೆ = ctx->bufsz = 0;
        ಮುಂದಿನ = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    ಆದರೆ (ಅಂಕೆ != 0) {
        ಆದರೆ (outlen > ctx->bufsz)
            len = ctx->bufsz;
        ಇಲ್ಲದಿದ್ದರೆ
            len = outlen;
        ಸ್ಮರಣೆ_ನಕಲು(ಹೊರಹೋಗು, ctx->buf + bsz - ctx->bufsz, len);
        ಹೊರಹೋಗು += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    ಆದರೆ (outlen == 0)
        ಹಿಂತಿರುಗಿ 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    ಆದರೆ (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, ಹೊರಹೋಗು, len, bsz, ಮುಂದಿನ);
        ಮುಂದಿನ = 1;
        ಹೊರಹೋಗು += len;
        outlen -= len;
    }
    ಆದರೆ (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, ಮುಂದಿನ);
        ಸ್ಮರಣೆ_ನಕಲು(ಹೊರಹೋಗು, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ PROV_SHA3_ವಿಧಾನ shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#ಆದರೆ defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
ಸ್ಥಿರ size_t sha3_absorb_s390x(KECCAK1600_CTX *ctx, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *inp, size_t len)
{
    size_t rem = len % ctx->ಖಂಡ_ಗಾತ್ರ;
    ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ fc;

    ಆದರೆ (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    ಹಿಂತಿರುಗಿ rem;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ shake_final_s390x(KECCAK1600_CTX *ctx, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು, size_t outlen)
{
    ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, ಹೊರಹೋಗು, outlen, fc, ctx->A);
    ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ shake_squeeze_s390x(KECCAK1600_CTX *ctx, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು, size_t outlen)
{
    ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ fc;
    size_t len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    ಆದರೆ (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, ಹೊರಹೋಗು, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->ಖಂಡ_ಗಾತ್ರ;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        ಹಿಂತಿರುಗಿ 1;
    }
    ಆದರೆ (ctx->bufsz != 0) {
        len = ctx->ಖಂಡ_ಗಾತ್ರ - ctx->bufsz;
        ಆದರೆ (outlen < len)
            len = outlen;
        ಸ್ಮರಣೆ_ನಕಲು(ಹೊರಹೋಗು, (ಅಕ್ಷರ *)ctx->A + ctx->bufsz, len);
        ಹೊರಹೋಗು += len;
        outlen -= len;
        ctx->bufsz += len;
        ಆದರೆ (ctx->bufsz == ctx->ಖಂಡ_ಗಾತ್ರ)
            ctx->bufsz = 0;
    }
    ಆದರೆ (outlen == 0)
        ಹಿಂತಿರುಗಿ 1;
    s390x_klmd(ಖಾಲಿ, 0, ಹೊರಹೋಗು, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->ಖಂಡ_ಗಾತ್ರ;

    ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ PROV_SHA3_ವಿಧಾನ shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#ಅಥವಾಆದರೆ defined(__aarch64__) && defined(KECCAK1600_ASM)

size_t SHA3_absorb_cext(uint64_t A[5][5], ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *inp, size_t len,
    size_t r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
ಸ್ಥಿರ size_t sha3_absorb_arm(KECCAK1600_CTX *ctx, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *inp, size_t len)
{
    ಹಿಂತಿರುಗಿ SHA3_absorb_cext(ctx->A, inp, len, ctx->ಖಂಡ_ಗಾತ್ರ);
}

ಸ್ಥಿರ PROV_SHA3_ವಿಧಾನ shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#ಆದರೆ_ಅಂತ್ಯ

KECCAK1600_CTX *ossl_shake256_new(ಶೂನ್ಯ)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(ಗಾತ್ರ(*ctx));

    ಆದರೆ (ctx == ಖಾಲಿ)
        ಹಿಂತಿರುಗಿ ಖಾಲಿ;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_ಗಾತ್ರ = ಗಾತ್ರ_MAX;
    ctx->meth = shake_generic_meth;
#ಆದರೆ defined(S390_SHA3)
    ಆದರೆ (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#ಅಥವಾಆದರೆ defined(__aarch64__) && defined(KECCAK1600_ASM)
    ಆದರೆ (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#ಆದರೆ_ಅಂತ್ಯ
    ಹಿಂತಿರುಗಿ ctx;
}
