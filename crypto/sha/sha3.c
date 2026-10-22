/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ "internal/sha3.h"
#অন্তর্ভাৱ "internal/common.h"

#যদি defined(__aarch64__) && defined(KECCAK1600_ASM)
#অন্তর্ভাৱ "arch/arm_arch.h"
#endif

#যদি defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#অন্তর্ভাৱ "arch/s390x_arch.h"
#যদি defined(KECCAK1600_ASM)
#define S390_SHA3 1
#define S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#endif
#endif

শূন্য SHA3_squeeze(uint64_t A[5][5], unsigned ৱর্ণ *out, size_t len, size_t r, পূর্ণাঙ্ক next);

শূন্য ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#যদি defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    যদি (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#endif
        memset(ctx->A, 0, পরিমাণ(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

পূর্ণাঙ্ক ossl_sha3_init(KECCAK1600_CTX *ctx, unsigned ৱর্ণ pad, size_t bitlen)
{
    size_t bsz = SHA3_BLOCKSIZE(bitlen);

    যদি (bsz <= পরিমাণ(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->block_size = bsz;
        ctx->md_size = bitlen / 8;
        ctx->pad = pad;
        ঘূৰাই 1;
    }

    ঘূৰাই 0;
}

পূর্ণাঙ্ক ossl_keccak_init(KECCAK1600_CTX *ctx, unsigned ৱর্ণ pad, size_t bitlen, size_t mdlen)
{
    পূর্ণাঙ্ক ret = ossl_sha3_init(ctx, pad, bitlen);

    যদি (ret)
        ctx->md_size = mdlen / 8;
    ঘূৰাই ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
পূর্ণাঙ্ক ossl_sha3_absorb(KECCAK1600_CTX *ctx, ধ্রুৱ unsigned ৱর্ণ *inp, size_t len)
{
    ধ্রুৱ size_t bsz = ctx->block_size;
    size_t অঙ্ক, rem;

    যদি (ossl_unlikely(len == 0))
        ঘূৰাই 1;

    যদি (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        ঘূৰাই 0;

    /* Is there anything in the buffer already ? */
    যদি ((অঙ্ক = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - অঙ্ক;
        /* If the new input does not fill the buffer then just add it */
        যদি (len < rem) {
            memcpy(ctx->buf + অঙ্ক, inp, len);
            ctx->bufsz += len;
            ঘূৰাই 1;
        }
        /* otherwise fill up the buffer and absorb the buffer */
        memcpy(ctx->buf + অঙ্ক, inp, rem);
        /* Update the input pointer */
        inp += rem;
        len -= rem;
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_ABSORB;
    }
    /* Absorb the input - rem = leftover part of the input < blocksize) */
    rem = ctx->meth.absorb(ctx, inp, len);
    যদি (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    যদি (ossl_likely(rem > 0)) {
        memcpy(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    ঘূৰাই 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
পূর্ণাঙ্ক ossl_sha3_final(KECCAK1600_CTX *ctx, unsigned ৱর্ণ *out, size_t outlen)
{
    পূর্ণাঙ্ক ret;

    যদি (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        ঘূৰাই 0;
    যদি (outlen == 0)
        ঘূৰাই 1;

    ret = ctx->meth.final(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    ঘূৰাই ret;
}

/* Calls a platform specific squeeze method */
পূর্ণাঙ্ক ossl_sha3_squeeze(KECCAK1600_CTX *ctx, unsigned ৱর্ণ *out, size_t outlen)
{
    পূর্ণাঙ্ক ret = 0;

    যদি (ctx->xof_state == XOF_STATE_FINAL)
        ঘূৰাই 0;
    ret = ctx->meth.squeeze(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    ঘূৰাই ret;
}

/* Default version of the absorb() */
size_t ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, ধ্রুৱ unsigned ৱর্ণ *inp, size_t len)
{
    ঘূৰাই SHA3_absorb(ctx->A, inp, len, ctx->block_size);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
পূর্ণাঙ্ক ossl_sha3_final_default(KECCAK1600_CTX *ctx, unsigned ৱর্ণ *out, size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t অঙ্ক = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + অঙ্ক, 0, bsz - অঙ্ক);
    ctx->buf[অঙ্ক] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (শূন্য)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, out, outlen, bsz, 0);
    ঘূৰাই 1;
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
পূর্ণাঙ্ক ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, unsigned ৱর্ণ *out, size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t অঙ্ক = ctx->bufsz;
    size_t len;
    পূর্ণাঙ্ক next = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    যদি (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + অঙ্ক, 0, bsz - অঙ্ক);
        ctx->buf[অঙ্ক] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (শূন্য)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        অঙ্ক = ctx->bufsz = 0;
        next = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    যদি (অঙ্ক != 0) {
        যদি (outlen > ctx->bufsz)
            len = ctx->bufsz;
        অন্যথা
            len = outlen;
        memcpy(out, ctx->buf + bsz - ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    যদি (outlen == 0)
        ঘূৰাই 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    যদি (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, out, len, bsz, next);
        next = 1;
        out += len;
        outlen -= len;
    }
    যদি (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, next);
        memcpy(out, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    ঘূৰাই 1;
}

স্থির PROV_SHA3_METHOD shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#যদি defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
স্থির size_t sha3_absorb_s390x(KECCAK1600_CTX *ctx, ধ্রুৱ unsigned ৱর্ণ *inp, size_t len)
{
    size_t rem = len % ctx->block_size;
    unsigned পূর্ণাঙ্ক fc;

    যদি (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    ঘূৰাই rem;
}

স্থির পূর্ণাঙ্ক shake_final_s390x(KECCAK1600_CTX *ctx, unsigned ৱর্ণ *out, size_t outlen)
{
    unsigned পূর্ণাঙ্ক fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
    ঘূৰাই 1;
}

স্থির পূর্ণাঙ্ক shake_squeeze_s390x(KECCAK1600_CTX *ctx, unsigned ৱর্ণ *out, size_t outlen)
{
    unsigned পূর্ণাঙ্ক fc;
    size_t len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    যদি (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->block_size;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        ঘূৰাই 1;
    }
    যদি (ctx->bufsz != 0) {
        len = ctx->block_size - ctx->bufsz;
        যদি (outlen < len)
            len = outlen;
        memcpy(out, (ৱর্ণ *)ctx->A + ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz += len;
        যদি (ctx->bufsz == ctx->block_size)
            ctx->bufsz = 0;
    }
    যদি (outlen == 0)
        ঘূৰাই 1;
    s390x_klmd(রিক্ত, 0, out, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->block_size;

    ঘূৰাই 1;
}

স্থির PROV_SHA3_METHOD shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#নোচেদ্যদি defined(__aarch64__) && defined(KECCAK1600_ASM)

size_t SHA3_absorb_cext(uint64_t A[5][5], ধ্রুৱ unsigned ৱর্ণ *inp, size_t len,
    size_t r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
স্থির size_t sha3_absorb_arm(KECCAK1600_CTX *ctx, ধ্রুৱ unsigned ৱর্ণ *inp, size_t len)
{
    ঘূৰাই SHA3_absorb_cext(ctx->A, inp, len, ctx->block_size);
}

স্থির PROV_SHA3_METHOD shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#endif

KECCAK1600_CTX *ossl_shake256_new(শূন্য)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(পরিমাণ(*ctx));

    যদি (ctx == রিক্ত)
        ঘূৰাই রিক্ত;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_size = SIZE_MAX;
    ctx->meth = shake_generic_meth;
#যদি defined(S390_SHA3)
    যদি (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#নোচেদ্যদি defined(__aarch64__) && defined(KECCAK1600_ASM)
    যদি (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#endif
    ঘূৰাই ctx;
}
