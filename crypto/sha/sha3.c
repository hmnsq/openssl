/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#அந்தர்பாவ <string.h>
#அந்தர்பாவ "internal/sha3.h"
#அந்தர்பாவ "internal/common.h"

#எனில் defined(__aarch64__) && defined(KECCAK1600_ASM)
#அந்தர்பாவ "arch/arm_arch.h"
#endif

#எனில் defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#அந்தர்பாவ "arch/s390x_arch.h"
#எனில் defined(KECCAK1600_ASM)
#define S390_SHA3 1
#define S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#endif
#endif

வெறுமை SHA3_squeeze(uint64_t A[5][5], unsigned எழுத்து *out, size_t len, size_t r, முழு next);

வெறுமை ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#எனில் defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    எனில் (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#endif
        memset(ctx->A, 0, அளவு(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

முழு ossl_sha3_init(KECCAK1600_CTX *ctx, unsigned எழுத்து pad, size_t bitlen)
{
    size_t bsz = SHA3_BLOCKSIZE(bitlen);

    எனில் (bsz <= அளவு(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->block_size = bsz;
        ctx->md_size = bitlen / 8;
        ctx->pad = pad;
        திரும்பு 1;
    }

    திரும்பு 0;
}

முழு ossl_keccak_init(KECCAK1600_CTX *ctx, unsigned எழுத்து pad, size_t bitlen, size_t mdlen)
{
    முழு ret = ossl_sha3_init(ctx, pad, bitlen);

    எனில் (ret)
        ctx->md_size = mdlen / 8;
    திரும்பு ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
முழு ossl_sha3_absorb(KECCAK1600_CTX *ctx, மாறிலி unsigned எழுத்து *inp, size_t len)
{
    மாறிலி size_t bsz = ctx->block_size;
    size_t இலக்கம், rem;

    எனில் (ossl_unlikely(len == 0))
        திரும்பு 1;

    எனில் (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        திரும்பு 0;

    /* Is there anything in the buffer already ? */
    எனில் ((இலக்கம் = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - இலக்கம்;
        /* If the new input does not fill the buffer then just add it */
        எனில் (len < rem) {
            memcpy(ctx->buf + இலக்கம், inp, len);
            ctx->bufsz += len;
            திரும்பு 1;
        }
        /* otherwise fill up the buffer and absorb the buffer */
        memcpy(ctx->buf + இலக்கம், inp, rem);
        /* Update the input pointer */
        inp += rem;
        len -= rem;
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_ABSORB;
    }
    /* Absorb the input - rem = leftover part of the input < blocksize) */
    rem = ctx->meth.absorb(ctx, inp, len);
    எனில் (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    எனில் (ossl_likely(rem > 0)) {
        memcpy(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    திரும்பு 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
முழு ossl_sha3_final(KECCAK1600_CTX *ctx, unsigned எழுத்து *out, size_t outlen)
{
    முழு ret;

    எனில் (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        திரும்பு 0;
    எனில் (outlen == 0)
        திரும்பு 1;

    ret = ctx->meth.final(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    திரும்பு ret;
}

/* Calls a platform specific squeeze method */
முழு ossl_sha3_squeeze(KECCAK1600_CTX *ctx, unsigned எழுத்து *out, size_t outlen)
{
    முழு ret = 0;

    எனில் (ctx->xof_state == XOF_STATE_FINAL)
        திரும்பு 0;
    ret = ctx->meth.squeeze(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    திரும்பு ret;
}

/* Default version of the absorb() */
size_t ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, மாறிலி unsigned எழுத்து *inp, size_t len)
{
    திரும்பு SHA3_absorb(ctx->A, inp, len, ctx->block_size);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
முழு ossl_sha3_final_default(KECCAK1600_CTX *ctx, unsigned எழுத்து *out, size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t இலக்கம் = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + இலக்கம், 0, bsz - இலக்கம்);
    ctx->buf[இலக்கம்] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (வெறுமை)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, out, outlen, bsz, 0);
    திரும்பு 1;
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
முழு ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, unsigned எழுத்து *out, size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t இலக்கம் = ctx->bufsz;
    size_t len;
    முழு next = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    எனில் (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + இலக்கம், 0, bsz - இலக்கம்);
        ctx->buf[இலக்கம்] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (வெறுமை)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        இலக்கம் = ctx->bufsz = 0;
        next = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    எனில் (இலக்கம் != 0) {
        எனில் (outlen > ctx->bufsz)
            len = ctx->bufsz;
        இல்லையெனில்
            len = outlen;
        memcpy(out, ctx->buf + bsz - ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    எனில் (outlen == 0)
        திரும்பு 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    எனில் (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, out, len, bsz, next);
        next = 1;
        out += len;
        outlen -= len;
    }
    எனில் (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, next);
        memcpy(out, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    திரும்பு 1;
}

நிலையான PROV_SHA3_METHOD shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#எனில் defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
நிலையான size_t sha3_absorb_s390x(KECCAK1600_CTX *ctx, மாறிலி unsigned எழுத்து *inp, size_t len)
{
    size_t rem = len % ctx->block_size;
    unsigned முழு fc;

    எனில் (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    திரும்பு rem;
}

நிலையான முழு shake_final_s390x(KECCAK1600_CTX *ctx, unsigned எழுத்து *out, size_t outlen)
{
    unsigned முழு fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
    திரும்பு 1;
}

நிலையான முழு shake_squeeze_s390x(KECCAK1600_CTX *ctx, unsigned எழுத்து *out, size_t outlen)
{
    unsigned முழு fc;
    size_t len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    எனில் (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->block_size;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        திரும்பு 1;
    }
    எனில் (ctx->bufsz != 0) {
        len = ctx->block_size - ctx->bufsz;
        எனில் (outlen < len)
            len = outlen;
        memcpy(out, (எழுத்து *)ctx->A + ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz += len;
        எனில் (ctx->bufsz == ctx->block_size)
            ctx->bufsz = 0;
    }
    எனில் (outlen == 0)
        திரும்பு 1;
    s390x_klmd(வெற்று, 0, out, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->block_size;

    திரும்பு 1;
}

நிலையான PROV_SHA3_METHOD shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#அல்லதெனில் defined(__aarch64__) && defined(KECCAK1600_ASM)

size_t SHA3_absorb_cext(uint64_t A[5][5], மாறிலி unsigned எழுத்து *inp, size_t len,
    size_t r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
நிலையான size_t sha3_absorb_arm(KECCAK1600_CTX *ctx, மாறிலி unsigned எழுத்து *inp, size_t len)
{
    திரும்பு SHA3_absorb_cext(ctx->A, inp, len, ctx->block_size);
}

நிலையான PROV_SHA3_METHOD shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#endif

KECCAK1600_CTX *ossl_shake256_new(வெறுமை)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(அளவு(*ctx));

    எனில் (ctx == வெற்று)
        திரும்பு வெற்று;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_size = SIZE_MAX;
    ctx->meth = shake_generic_meth;
#எனில் defined(S390_SHA3)
    எனில் (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#அல்லதெனில் defined(__aarch64__) && defined(KECCAK1600_ASM)
    எனில் (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#endif
    திரும்பு ctx;
}
