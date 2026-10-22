/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "internal/sha3.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "internal/common.h"

#ਜੇ defined(__aarch64__) && defined(KECCAK1600_ASM)
#ਅਨ੍ਤਰ੍ਭਾਵ "arch/arm_arch.h"
#ਜੇ_ਅੰਤ

#ਜੇ defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#ਅਨ੍ਤਰ੍ਭਾਵ "arch/s390x_arch.h"
#ਜੇ defined(KECCAK1600_ASM)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ S390_SHA3 1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ

ਖਾਲੀ SHA3_squeeze(uint64_t A[5][5], ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ, size_t len, size_t r, ਪੂਰਨ ਅਗਲਾ);

ਖਾਲੀ ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#ਜੇ defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    ਜੇ (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#ਜੇ_ਅੰਤ
        memset(ctx->A, 0, ਆਕਾਰ(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

ਪੂਰਨ ossl_sha3_init(KECCAK1600_CTX *ctx, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ pad, size_t bitlen)
{
    size_t bsz = SHA3_BLOCKSIZE(bitlen);

    ਜੇ (bsz <= ਆਕਾਰ(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->ਖੰਡ_ਮਾਪ = bsz;
        ctx->md_ਮਾਪ = bitlen / 8;
        ctx->pad = pad;
        ਵਾਪਸ 1;
    }

    ਵਾਪਸ 0;
}

ਪੂਰਨ ossl_keccak_init(KECCAK1600_CTX *ctx, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ pad, size_t bitlen, size_t mdlen)
{
    ਪੂਰਨ ret = ossl_sha3_init(ctx, pad, bitlen);

    ਜੇ (ret)
        ctx->md_ਮਾਪ = mdlen / 8;
    ਵਾਪਸ ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
ਪੂਰਨ ossl_sha3_absorb(KECCAK1600_CTX *ctx, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *inp, size_t len)
{
    ਅਚਲ size_t bsz = ctx->ਖੰਡ_ਮਾਪ;
    size_t ਅੰਕ, rem;

    ਜੇ (ossl_unlikely(len == 0))
        ਵਾਪਸ 1;

    ਜੇ (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        ਵਾਪਸ 0;

    /* Is there anything in the buffer already ? */
    ਜੇ ((ਅੰਕ = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - ਅੰਕ;
        /* If the new input does not fill the buffer then just add it */
        ਜੇ (len < rem) {
            ਸਮ੍ਰਿਤੀ_ਨਕਲ(ctx->buf + ਅੰਕ, inp, len);
            ctx->bufsz += len;
            ਵਾਪਸ 1;
        }
        /* otherwise fill up the buffer and absorb the buffer */
        ਸਮ੍ਰਿਤੀ_ਨਕਲ(ctx->buf + ਅੰਕ, inp, rem);
        /* Update the input pointer */
        inp += rem;
        len -= rem;
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_ABSORB;
    }
    /* Absorb the input - rem = leftover part of the input < blocksize) */
    rem = ctx->meth.absorb(ctx, inp, len);
    ਜੇ (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    ਜੇ (ossl_likely(rem > 0)) {
        ਸਮ੍ਰਿਤੀ_ਨਕਲ(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    ਵਾਪਸ 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
ਪੂਰਨ ossl_sha3_final(KECCAK1600_CTX *ctx, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ, size_t outlen)
{
    ਪੂਰਨ ret;

    ਜੇ (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        ਵਾਪਸ 0;
    ਜੇ (outlen == 0)
        ਵਾਪਸ 1;

    ret = ctx->meth.final(ctx, ਬਾਹਰਲਾ, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    ਵਾਪਸ ret;
}

/* Calls a platform specific squeeze method */
ਪੂਰਨ ossl_sha3_squeeze(KECCAK1600_CTX *ctx, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ, size_t outlen)
{
    ਪੂਰਨ ret = 0;

    ਜੇ (ctx->xof_state == XOF_STATE_FINAL)
        ਵਾਪਸ 0;
    ret = ctx->meth.squeeze(ctx, ਬਾਹਰਲਾ, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    ਵਾਪਸ ret;
}

/* Default version of the absorb() */
size_t ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *inp, size_t len)
{
    ਵਾਪਸ SHA3_absorb(ctx->A, inp, len, ctx->ਖੰਡ_ਮਾਪ);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
ਪੂਰਨ ossl_sha3_final_default(KECCAK1600_CTX *ctx, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ, size_t outlen)
{
    size_t bsz = ctx->ਖੰਡ_ਮਾਪ;
    size_t ਅੰਕ = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + ਅੰਕ, 0, bsz - ਅੰਕ);
    ctx->buf[ਅੰਕ] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (ਖਾਲੀ)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, ਬਾਹਰਲਾ, outlen, bsz, 0);
    ਵਾਪਸ 1;
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
ਪੂਰਨ ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ, size_t outlen)
{
    size_t bsz = ctx->ਖੰਡ_ਮਾਪ;
    size_t ਅੰਕ = ctx->bufsz;
    size_t len;
    ਪੂਰਨ ਅਗਲਾ = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    ਜੇ (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + ਅੰਕ, 0, bsz - ਅੰਕ);
        ctx->buf[ਅੰਕ] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (ਖਾਲੀ)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        ਅੰਕ = ctx->bufsz = 0;
        ਅਗਲਾ = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    ਜੇ (ਅੰਕ != 0) {
        ਜੇ (outlen > ctx->bufsz)
            len = ctx->bufsz;
        ਨਹੀਂਤਾਂ
            len = outlen;
        ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਬਾਹਰਲਾ, ctx->buf + bsz - ctx->bufsz, len);
        ਬਾਹਰਲਾ += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    ਜੇ (outlen == 0)
        ਵਾਪਸ 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    ਜੇ (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, ਬਾਹਰਲਾ, len, bsz, ਅਗਲਾ);
        ਅਗਲਾ = 1;
        ਬਾਹਰਲਾ += len;
        outlen -= len;
    }
    ਜੇ (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, ਅਗਲਾ);
        ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਬਾਹਰਲਾ, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    ਵਾਪਸ 1;
}

ਸਥਿਰ PROV_SHA3_ਵਿਧੀ shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#ਜੇ defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
ਸਥਿਰ size_t sha3_absorb_s390x(KECCAK1600_CTX *ctx, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *inp, size_t len)
{
    size_t rem = len % ctx->ਖੰਡ_ਮਾਪ;
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ fc;

    ਜੇ (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    ਵਾਪਸ rem;
}

ਸਥਿਰ ਪੂਰਨ shake_final_s390x(KECCAK1600_CTX *ctx, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ, size_t outlen)
{
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, ਬਾਹਰਲਾ, outlen, fc, ctx->A);
    ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ shake_squeeze_s390x(KECCAK1600_CTX *ctx, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ, size_t outlen)
{
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ fc;
    size_t len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    ਜੇ (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, ਬਾਹਰਲਾ, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->ਖੰਡ_ਮਾਪ;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        ਵਾਪਸ 1;
    }
    ਜੇ (ctx->bufsz != 0) {
        len = ctx->ਖੰਡ_ਮਾਪ - ctx->bufsz;
        ਜੇ (outlen < len)
            len = outlen;
        ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਬਾਹਰਲਾ, (ਅੱਖਰ *)ctx->A + ctx->bufsz, len);
        ਬਾਹਰਲਾ += len;
        outlen -= len;
        ctx->bufsz += len;
        ਜੇ (ctx->bufsz == ctx->ਖੰਡ_ਮਾਪ)
            ctx->bufsz = 0;
    }
    ਜੇ (outlen == 0)
        ਵਾਪਸ 1;
    s390x_klmd(ਨਿਰਾ, 0, ਬਾਹਰਲਾ, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->ਖੰਡ_ਮਾਪ;

    ਵਾਪਸ 1;
}

ਸਥਿਰ PROV_SHA3_ਵਿਧੀ shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#ਜਾਂਜੇ defined(__aarch64__) && defined(KECCAK1600_ASM)

size_t SHA3_absorb_cext(uint64_t A[5][5], ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *inp, size_t len,
    size_t r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
ਸਥਿਰ size_t sha3_absorb_arm(KECCAK1600_CTX *ctx, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *inp, size_t len)
{
    ਵਾਪਸ SHA3_absorb_cext(ctx->A, inp, len, ctx->ਖੰਡ_ਮਾਪ);
}

ਸਥਿਰ PROV_SHA3_ਵਿਧੀ shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#ਜੇ_ਅੰਤ

KECCAK1600_CTX *ossl_shake256_new(ਖਾਲੀ)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(ਆਕਾਰ(*ctx));

    ਜੇ (ctx == ਨਿਰਾ)
        ਵਾਪਸ ਨਿਰਾ;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_ਮਾਪ = ਮਾਪ_MAX;
    ctx->meth = shake_generic_meth;
#ਜੇ defined(S390_SHA3)
    ਜੇ (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#ਜਾਂਜੇ defined(__aarch64__) && defined(KECCAK1600_ASM)
    ਜੇ (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#ਜੇ_ਅੰਤ
    ਵਾਪਸ ctx;
}
