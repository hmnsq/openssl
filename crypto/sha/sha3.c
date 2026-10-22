/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#अन्तर्भाव <string.h>
#अन्तर्भाव "internal/sha3.h"
#अन्तर्भाव "internal/common.h"

#यदि defined(__aarch64__) && defined(KECCAK1600_ASM)
#अन्तर्भाव "arch/arm_arch.h"
#यदि_अन्तः

#यदि defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#अन्तर्भाव "arch/s390x_arch.h"
#यदि defined(KECCAK1600_ASM)
#परिभाषय S390_SHA3 1
#परिभाषय S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#यदि_अन्तः
#यदि_अन्तः

शून्य SHA3_squeeze(uint64_t A[5][5], अचिह्नित वर्ण *बहिर्गमनम्, size_t len, size_t r, पूर्णाङ्क अग्र);

शून्य ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#यदि defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    यदि (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#यदि_अन्तः
        स्मृतिं_पूरय(ctx->A, 0, परिमाण(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

पूर्णाङ्क ossl_sha3_init(KECCAK1600_CTX *ctx, अचिह्नित वर्ण pad, size_t bitlen)
{
    size_t bsz = SHA3_BLOCKSIZE(bitlen);

    यदि (bsz <= परिमाण(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->खण्डम्_आकार = bsz;
        ctx->md_आकार = bitlen / 8;
        ctx->pad = pad;
        प्रत्यागम 1;
    }

    प्रत्यागम 0;
}

पूर्णाङ्क ossl_keccak_init(KECCAK1600_CTX *ctx, अचिह्नित वर्ण pad, size_t bitlen, size_t mdlen)
{
    पूर्णाङ्क ret = ossl_sha3_init(ctx, pad, bitlen);

    यदि (ret)
        ctx->md_आकार = mdlen / 8;
    प्रत्यागम ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
पूर्णाङ्क ossl_sha3_absorb(KECCAK1600_CTX *ctx, ध्रुव अचिह्नित वर्ण *inp, size_t len)
{
    ध्रुव size_t bsz = ctx->खण्डम्_आकार;
    size_t अङ्कः, rem;

    यदि (ossl_unlikely(len == 0))
        प्रत्यागम 1;

    यदि (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        प्रत्यागम 0;

    /* Is there anything in the buffer already ? */
    यदि ((अङ्कः = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - अङ्कः;
        /* If the new input does not fill the buffer then just add it */
        यदि (len < rem) {
            स्मृतिं_प्रतिलिख(ctx->buf + अङ्कः, inp, len);
            ctx->bufsz += len;
            प्रत्यागम 1;
        }
        /* otherwise fill up the buffer and absorb the buffer */
        स्मृतिं_प्रतिलिख(ctx->buf + अङ्कः, inp, rem);
        /* Update the input pointer */
        inp += rem;
        len -= rem;
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_ABSORB;
    }
    /* Absorb the input - rem = leftover part of the input < blocksize) */
    rem = ctx->meth.absorb(ctx, inp, len);
    यदि (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    यदि (ossl_likely(rem > 0)) {
        स्मृतिं_प्रतिलिख(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    प्रत्यागम 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
पूर्णाङ्क ossl_sha3_final(KECCAK1600_CTX *ctx, अचिह्नित वर्ण *बहिर्गमनम्, size_t outlen)
{
    पूर्णाङ्क ret;

    यदि (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        प्रत्यागम 0;
    यदि (outlen == 0)
        प्रत्यागम 1;

    ret = ctx->meth.final(ctx, बहिर्गमनम्, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    प्रत्यागम ret;
}

/* Calls a platform specific squeeze method */
पूर्णाङ्क ossl_sha3_squeeze(KECCAK1600_CTX *ctx, अचिह्नित वर्ण *बहिर्गमनम्, size_t outlen)
{
    पूर्णाङ्क ret = 0;

    यदि (ctx->xof_state == XOF_STATE_FINAL)
        प्रत्यागम 0;
    ret = ctx->meth.squeeze(ctx, बहिर्गमनम्, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    प्रत्यागम ret;
}

/* Default version of the absorb() */
size_t ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, ध्रुव अचिह्नित वर्ण *inp, size_t len)
{
    प्रत्यागम SHA3_absorb(ctx->A, inp, len, ctx->खण्डम्_आकार);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
पूर्णाङ्क ossl_sha3_final_default(KECCAK1600_CTX *ctx, अचिह्नित वर्ण *बहिर्गमनम्, size_t outlen)
{
    size_t bsz = ctx->खण्डम्_आकार;
    size_t अङ्कः = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    स्मृतिं_पूरय(ctx->buf + अङ्कः, 0, bsz - अङ्कः);
    ctx->buf[अङ्कः] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (शून्य)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, बहिर्गमनम्, outlen, bsz, 0);
    प्रत्यागम 1;
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
पूर्णाङ्क ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, अचिह्नित वर्ण *बहिर्गमनम्, size_t outlen)
{
    size_t bsz = ctx->खण्डम्_आकार;
    size_t अङ्कः = ctx->bufsz;
    size_t len;
    पूर्णाङ्क अग्र = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    यदि (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        स्मृतिं_पूरय(ctx->buf + अङ्कः, 0, bsz - अङ्कः);
        ctx->buf[अङ्कः] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (शून्य)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        अङ्कः = ctx->bufsz = 0;
        अग्र = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    यदि (अङ्कः != 0) {
        यदि (outlen > ctx->bufsz)
            len = ctx->bufsz;
        अन्यथा
            len = outlen;
        स्मृतिं_प्रतिलिख(बहिर्गमनम्, ctx->buf + bsz - ctx->bufsz, len);
        बहिर्गमनम् += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    यदि (outlen == 0)
        प्रत्यागम 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    यदि (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, बहिर्गमनम्, len, bsz, अग्र);
        अग्र = 1;
        बहिर्गमनम् += len;
        outlen -= len;
    }
    यदि (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, अग्र);
        स्मृतिं_प्रतिलिख(बहिर्गमनम्, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    प्रत्यागम 1;
}

स्थिर PROV_SHA3_विधानम् shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#यदि defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
स्थिर size_t sha3_absorb_s390x(KECCAK1600_CTX *ctx, ध्रुव अचिह्नित वर्ण *inp, size_t len)
{
    size_t rem = len % ctx->खण्डम्_आकार;
    अचिह्नित पूर्णाङ्क fc;

    यदि (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    प्रत्यागम rem;
}

स्थिर पूर्णाङ्क shake_final_s390x(KECCAK1600_CTX *ctx, अचिह्नित वर्ण *बहिर्गमनम्, size_t outlen)
{
    अचिह्नित पूर्णाङ्क fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, बहिर्गमनम्, outlen, fc, ctx->A);
    प्रत्यागम 1;
}

स्थिर पूर्णाङ्क shake_squeeze_s390x(KECCAK1600_CTX *ctx, अचिह्नित वर्ण *बहिर्गमनम्, size_t outlen)
{
    अचिह्नित पूर्णाङ्क fc;
    size_t len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    यदि (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, बहिर्गमनम्, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->खण्डम्_आकार;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        प्रत्यागम 1;
    }
    यदि (ctx->bufsz != 0) {
        len = ctx->खण्डम्_आकार - ctx->bufsz;
        यदि (outlen < len)
            len = outlen;
        स्मृतिं_प्रतिलिख(बहिर्गमनम्, (वर्ण *)ctx->A + ctx->bufsz, len);
        बहिर्गमनम् += len;
        outlen -= len;
        ctx->bufsz += len;
        यदि (ctx->bufsz == ctx->खण्डम्_आकार)
            ctx->bufsz = 0;
    }
    यदि (outlen == 0)
        प्रत्यागम 1;
    s390x_klmd(रिक्त, 0, बहिर्गमनम्, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->खण्डम्_आकार;

    प्रत्यागम 1;
}

स्थिर PROV_SHA3_विधानम् shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#नोचेद्यदि defined(__aarch64__) && defined(KECCAK1600_ASM)

size_t SHA3_absorb_cext(uint64_t A[5][5], ध्रुव अचिह्नित वर्ण *inp, size_t len,
    size_t r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
स्थिर size_t sha3_absorb_arm(KECCAK1600_CTX *ctx, ध्रुव अचिह्नित वर्ण *inp, size_t len)
{
    प्रत्यागम SHA3_absorb_cext(ctx->A, inp, len, ctx->खण्डम्_आकार);
}

स्थिर PROV_SHA3_विधानम् shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#यदि_अन्तः

KECCAK1600_CTX *ossl_shake256_new(शून्य)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(परिमाण(*ctx));

    यदि (ctx == रिक्त)
        प्रत्यागम रिक्त;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_आकार = आकार_MAX;
    ctx->meth = shake_generic_meth;
#यदि defined(S390_SHA3)
    यदि (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#नोचेद्यदि defined(__aarch64__) && defined(KECCAK1600_ASM)
    यदि (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#यदि_अन्तः
    प्रत्यागम ctx;
}
