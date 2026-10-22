/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ "internal/sha3.h"
#અન્તર્ભાવ "internal/common.h"

#જો defined(__aarch64__) && defined(KECCAK1600_ASM)
#અન્તર્ભાવ "arch/arm_arch.h"
#endif

#જો defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#અન્તર્ભાવ "arch/s390x_arch.h"
#જો defined(KECCAK1600_ASM)
#define S390_SHA3 1
#define S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#endif
#endif

શૂન્ય SHA3_squeeze(uint64_t A[5][5], unsigned અક્ષર *out, size_t len, size_t r, પૂર્ણાંક next);

શૂન્ય ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#જો defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    જો (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#endif
        memset(ctx->A, 0, કદ(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

પૂર્ણાંક ossl_sha3_init(KECCAK1600_CTX *ctx, unsigned અક્ષર pad, size_t bitlen)
{
    size_t bsz = SHA3_BLOCKSIZE(bitlen);

    જો (bsz <= કદ(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->block_size = bsz;
        ctx->md_size = bitlen / 8;
        ctx->pad = pad;
        પાછા 1;
    }

    પાછા 0;
}

પૂર્ણાંક ossl_keccak_init(KECCAK1600_CTX *ctx, unsigned અક્ષર pad, size_t bitlen, size_t mdlen)
{
    પૂર્ણાંક ret = ossl_sha3_init(ctx, pad, bitlen);

    જો (ret)
        ctx->md_size = mdlen / 8;
    પાછા ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
પૂર્ણાંક ossl_sha3_absorb(KECCAK1600_CTX *ctx, અચલ unsigned અક્ષર *inp, size_t len)
{
    અચલ size_t bsz = ctx->block_size;
    size_t અંક, rem;

    જો (ossl_unlikely(len == 0))
        પાછા 1;

    જો (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        પાછા 0;

    /* Is there anything in the buffer already ? */
    જો ((અંક = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - અંક;
        /* If the new input does not fill the buffer then just add it */
        જો (len < rem) {
            memcpy(ctx->buf + અંક, inp, len);
            ctx->bufsz += len;
            પાછા 1;
        }
        /* otherwise fill up the buffer and absorb the buffer */
        memcpy(ctx->buf + અંક, inp, rem);
        /* Update the input pointer */
        inp += rem;
        len -= rem;
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_ABSORB;
    }
    /* Absorb the input - rem = leftover part of the input < blocksize) */
    rem = ctx->meth.absorb(ctx, inp, len);
    જો (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    જો (ossl_likely(rem > 0)) {
        memcpy(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    પાછા 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
પૂર્ણાંક ossl_sha3_final(KECCAK1600_CTX *ctx, unsigned અક્ષર *out, size_t outlen)
{
    પૂર્ણાંક ret;

    જો (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        પાછા 0;
    જો (outlen == 0)
        પાછા 1;

    ret = ctx->meth.final(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    પાછા ret;
}

/* Calls a platform specific squeeze method */
પૂર્ણાંક ossl_sha3_squeeze(KECCAK1600_CTX *ctx, unsigned અક્ષર *out, size_t outlen)
{
    પૂર્ણાંક ret = 0;

    જો (ctx->xof_state == XOF_STATE_FINAL)
        પાછા 0;
    ret = ctx->meth.squeeze(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    પાછા ret;
}

/* Default version of the absorb() */
size_t ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, અચલ unsigned અક્ષર *inp, size_t len)
{
    પાછા SHA3_absorb(ctx->A, inp, len, ctx->block_size);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
પૂર્ણાંક ossl_sha3_final_default(KECCAK1600_CTX *ctx, unsigned અક્ષર *out, size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t અંક = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + અંક, 0, bsz - અંક);
    ctx->buf[અંક] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (શૂન્ય)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, out, outlen, bsz, 0);
    પાછા 1;
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
પૂર્ણાંક ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, unsigned અક્ષર *out, size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t અંક = ctx->bufsz;
    size_t len;
    પૂર્ણાંક next = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    જો (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + અંક, 0, bsz - અંક);
        ctx->buf[અંક] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (શૂન્ય)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        અંક = ctx->bufsz = 0;
        next = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    જો (અંક != 0) {
        જો (outlen > ctx->bufsz)
            len = ctx->bufsz;
        નહીંતર
            len = outlen;
        memcpy(out, ctx->buf + bsz - ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    જો (outlen == 0)
        પાછા 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    જો (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, out, len, bsz, next);
        next = 1;
        out += len;
        outlen -= len;
    }
    જો (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, next);
        memcpy(out, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    પાછા 1;
}

સ્થિર PROV_SHA3_METHOD shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#જો defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
સ્થિર size_t sha3_absorb_s390x(KECCAK1600_CTX *ctx, અચલ unsigned અક્ષર *inp, size_t len)
{
    size_t rem = len % ctx->block_size;
    unsigned પૂર્ણાંક fc;

    જો (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    પાછા rem;
}

સ્થિર પૂર્ણાંક shake_final_s390x(KECCAK1600_CTX *ctx, unsigned અક્ષર *out, size_t outlen)
{
    unsigned પૂર્ણાંક fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
    પાછા 1;
}

સ્થિર પૂર્ણાંક shake_squeeze_s390x(KECCAK1600_CTX *ctx, unsigned અક્ષર *out, size_t outlen)
{
    unsigned પૂર્ણાંક fc;
    size_t len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    જો (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->block_size;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        પાછા 1;
    }
    જો (ctx->bufsz != 0) {
        len = ctx->block_size - ctx->bufsz;
        જો (outlen < len)
            len = outlen;
        memcpy(out, (અક્ષર *)ctx->A + ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz += len;
        જો (ctx->bufsz == ctx->block_size)
            ctx->bufsz = 0;
    }
    જો (outlen == 0)
        પાછા 1;
    s390x_klmd(ખાલી, 0, out, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->block_size;

    પાછા 1;
}

સ્થિર PROV_SHA3_METHOD shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#અથવાજો defined(__aarch64__) && defined(KECCAK1600_ASM)

size_t SHA3_absorb_cext(uint64_t A[5][5], અચલ unsigned અક્ષર *inp, size_t len,
    size_t r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
સ્થિર size_t sha3_absorb_arm(KECCAK1600_CTX *ctx, અચલ unsigned અક્ષર *inp, size_t len)
{
    પાછા SHA3_absorb_cext(ctx->A, inp, len, ctx->block_size);
}

સ્થિર PROV_SHA3_METHOD shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#endif

KECCAK1600_CTX *ossl_shake256_new(શૂન્ય)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(કદ(*ctx));

    જો (ctx == ખાલી)
        પાછા ખાલી;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_size = SIZE_MAX;
    ctx->meth = shake_generic_meth;
#જો defined(S390_SHA3)
    જો (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#અથવાજો defined(__aarch64__) && defined(KECCAK1600_ASM)
    જો (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#endif
    પાછા ctx;
}
