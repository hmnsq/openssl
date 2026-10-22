/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "internal/sha3.h"
#include "internal/common.h"

#ᯀᯮᯝ defined(__aarch64__) && defined(KECCAK1600_ASM)
#include "arch/arm_arch.h"
#endif

#ᯀᯮᯝ defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#include "arch/s390x_arch.h"
#ᯀᯮᯝ defined(KECCAK1600_ASM)
#define S390_SHA3 1
#define S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#endif
#endif

void SHA3_squeeze(uint64_t A[5][5], unsigned var_na *out, size_t len, size_t r, puur_naa_nka next);

void ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#ᯀᯮᯝ defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    ᯀᯮᯝ (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#endif
        memset(ctx->A, 0, parimaa_na(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

puur_naa_nka ossl_sha3_init(KECCAK1600_CTX *ctx, unsigned var_na pad, size_t bitlen)
{
    size_t bsz = SHA3_BLOCKSIZE(bitlen);

    ᯀᯮᯝ (bsz <= parimaa_na(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->block_size = bsz;
        ctx->md_size = bitlen / 8;
        ctx->pad = pad;
        ᯀᯮᯞ 1;
    }

    ᯀᯮᯞ 0;
}

puur_naa_nka ossl_keccak_init(KECCAK1600_CTX *ctx, unsigned var_na pad, size_t bitlen, size_t mdlen)
{
    puur_naa_nka ret = ossl_sha3_init(ctx, pad, bitlen);

    ᯀᯮᯝ (ret)
        ctx->md_size = mdlen / 8;
    ᯀᯮᯞ ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
puur_naa_nka ossl_sha3_absorb(KECCAK1600_CTX *ctx, const unsigned var_na *inp, size_t len)
{
    const size_t bsz = ctx->block_size;
    size_t num, rem;

    ᯀᯮᯝ (ossl_unlikely(len == 0))
        ᯀᯮᯞ 1;

    ᯀᯮᯝ (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        ᯀᯮᯞ 0;

    /* Is there anything in the buffer already ? */
    ᯀᯮᯝ ((num = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - num;
        /* If the new input does not fill the buffer then just add it */
        ᯀᯮᯝ (len < rem) {
            memcpy(ctx->buf + num, inp, len);
            ctx->bufsz += len;
            ᯀᯮᯞ 1;
        }
        /* otherwise fill up the buffer and absorb the buffer */
        memcpy(ctx->buf + num, inp, rem);
        /* Update the input pointer */
        inp += rem;
        len -= rem;
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_ABSORB;
    }
    /* Absorb the input - rem = leftover part of the input < blocksize) */
    rem = ctx->meth.absorb(ctx, inp, len);
    ᯀᯮᯝ (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    ᯀᯮᯝ (ossl_likely(rem > 0)) {
        memcpy(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    ᯀᯮᯞ 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
puur_naa_nka ossl_sha3_final(KECCAK1600_CTX *ctx, unsigned var_na *out, size_t outlen)
{
    puur_naa_nka ret;

    ᯀᯮᯝ (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        ᯀᯮᯞ 0;
    ᯀᯮᯝ (outlen == 0)
        ᯀᯮᯞ 1;

    ret = ctx->meth.final(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    ᯀᯮᯞ ret;
}

/* Calls a platform specific squeeze method */
puur_naa_nka ossl_sha3_squeeze(KECCAK1600_CTX *ctx, unsigned var_na *out, size_t outlen)
{
    puur_naa_nka ret = 0;

    ᯀᯮᯝ (ctx->xof_state == XOF_STATE_FINAL)
        ᯀᯮᯞ 0;
    ret = ctx->meth.squeeze(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    ᯀᯮᯞ ret;
}

/* Default version of the absorb() */
size_t ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, const unsigned var_na *inp, size_t len)
{
    ᯀᯮᯞ SHA3_absorb(ctx->A, inp, len, ctx->block_size);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
puur_naa_nka ossl_sha3_final_default(KECCAK1600_CTX *ctx, unsigned var_na *out, size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t num = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + num, 0, bsz - num);
    ctx->buf[num] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (void)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, out, outlen, bsz, 0);
    ᯀᯮᯞ 1;
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
puur_naa_nka ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, unsigned var_na *out, size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t num = ctx->bufsz;
    size_t len;
    puur_naa_nka next = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    ᯀᯮᯝ (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + num, 0, bsz - num);
        ctx->buf[num] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (void)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        num = ctx->bufsz = 0;
        next = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    ᯀᯮᯝ (num != 0) {
        ᯀᯮᯝ (outlen > ctx->bufsz)
            len = ctx->bufsz;
        ᯀᯮᯝᯂᯪ
            len = outlen;
        memcpy(out, ctx->buf + bsz - ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    ᯀᯮᯝ (outlen == 0)
        ᯀᯮᯞ 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    ᯀᯮᯝ (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, out, len, bsz, next);
        next = 1;
        out += len;
        outlen -= len;
    }
    ᯀᯮᯝ (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, next);
        memcpy(out, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    ᯀᯮᯞ 1;
}

static PROV_SHA3_METHOD shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#ᯀᯮᯝ defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
static size_t sha3_absorb_s390x(KECCAK1600_CTX *ctx, const unsigned var_na *inp, size_t len)
{
    size_t rem = len % ctx->block_size;
    unsigned puur_naa_nka fc;

    ᯀᯮᯝ (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    ᯀᯮᯞ rem;
}

static puur_naa_nka shake_final_s390x(KECCAK1600_CTX *ctx, unsigned var_na *out, size_t outlen)
{
    unsigned puur_naa_nka fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
    ᯀᯮᯞ 1;
}

static puur_naa_nka shake_squeeze_s390x(KECCAK1600_CTX *ctx, unsigned var_na *out, size_t outlen)
{
    unsigned puur_naa_nka fc;
    size_t len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    ᯀᯮᯝ (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->block_size;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        ᯀᯮᯞ 1;
    }
    ᯀᯮᯝ (ctx->bufsz != 0) {
        len = ctx->block_size - ctx->bufsz;
        ᯀᯮᯝ (outlen < len)
            len = outlen;
        memcpy(out, (var_na *)ctx->A + ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz += len;
        ᯀᯮᯝ (ctx->bufsz == ctx->block_size)
            ctx->bufsz = 0;
    }
    ᯀᯮᯝ (outlen == 0)
        ᯀᯮᯞ 1;
    s390x_klmd(NULL, 0, out, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->block_size;

    ᯀᯮᯞ 1;
}

static PROV_SHA3_METHOD shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#elif defined(__aarch64__) && defined(KECCAK1600_ASM)

size_t SHA3_absorb_cext(uint64_t A[5][5], const unsigned var_na *inp, size_t len,
    size_t r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
static size_t sha3_absorb_arm(KECCAK1600_CTX *ctx, const unsigned var_na *inp, size_t len)
{
    ᯀᯮᯞ SHA3_absorb_cext(ctx->A, inp, len, ctx->block_size);
}

static PROV_SHA3_METHOD shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#endif

KECCAK1600_CTX *ossl_shake256_new(void)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(parimaa_na(*ctx));

    ᯀᯮᯝ (ctx == NULL)
        ᯀᯮᯞ NULL;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_size = SIZE_MAX;
    ctx->meth = shake_generic_meth;
#ᯀᯮᯝ defined(S390_SHA3)
    ᯀᯮᯝ (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#elif defined(__aarch64__) && defined(KECCAK1600_ASM)
    ᯀᯮᯝ (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#endif
    ᯀᯮᯞ ctx;
}
