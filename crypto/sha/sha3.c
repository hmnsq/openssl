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

#जर defined(__aarch64__) && defined(KECCAK1600_ASM)
#अन्तर्भाव "arch/arm_arch.h"
#endif

#जर defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#अन्तर्भाव "arch/s390x_arch.h"
#जर defined(KECCAK1600_ASM)
#define S390_SHA3 1
#define S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#endif
#endif

शून्य SHA3_squeeze(uint64_t A[5][5], अचिन्हित अक्षर *out, माप_प्रकार len, माप_प्रकार r, पूर्णांक next);

शून्य ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#जर defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    जर (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#endif
        स_रखो(ctx->A, 0, आकार(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

पूर्णांक ossl_sha3_init(KECCAK1600_CTX *ctx, अचिन्हित अक्षर pad, माप_प्रकार bitlen)
{
    माप_प्रकार bsz = SHA3_BLOCKSIZE(bitlen);

    जर (bsz <= आकार(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->block_size = bsz;
        ctx->md_size = bitlen / 8;
        ctx->pad = pad;
        परत 1;
    }

    परत 0;
}

पूर्णांक ossl_keccak_init(KECCAK1600_CTX *ctx, अचिन्हित अक्षर pad, माप_प्रकार bitlen, माप_प्रकार mdlen)
{
    पूर्णांक ret = ossl_sha3_init(ctx, pad, bitlen);

    जर (ret)
        ctx->md_size = mdlen / 8;
    परत ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
पूर्णांक ossl_sha3_absorb(KECCAK1600_CTX *ctx, स्थिरांक अचिन्हित अक्षर *inp, माप_प्रकार len)
{
    स्थिरांक माप_प्रकार bsz = ctx->block_size;
    माप_प्रकार अंक, rem;

    जर (ossl_unlikely(len == 0))
        परत 1;

    जर (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        परत 0;

    /* Is there anything in the buffer already ? */
    जर ((अंक = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - अंक;
        /* If the new input does not fill the buffer then just add it */
        जर (len < rem) {
            स_नकल(ctx->buf + अंक, inp, len);
            ctx->bufsz += len;
            परत 1;
        }
        /* otherwise fill up the buffer and absorb the buffer */
        स_नकल(ctx->buf + अंक, inp, rem);
        /* Update the input pointer */
        inp += rem;
        len -= rem;
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_ABSORB;
    }
    /* Absorb the input - rem = leftover part of the input < blocksize) */
    rem = ctx->meth.absorb(ctx, inp, len);
    जर (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    जर (ossl_likely(rem > 0)) {
        स_नकल(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    परत 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
पूर्णांक ossl_sha3_final(KECCAK1600_CTX *ctx, अचिन्हित अक्षर *out, माप_प्रकार outlen)
{
    पूर्णांक ret;

    जर (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        परत 0;
    जर (outlen == 0)
        परत 1;

    ret = ctx->meth.final(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    परत ret;
}

/* Calls a platform specific squeeze method */
पूर्णांक ossl_sha3_squeeze(KECCAK1600_CTX *ctx, अचिन्हित अक्षर *out, माप_प्रकार outlen)
{
    पूर्णांक ret = 0;

    जर (ctx->xof_state == XOF_STATE_FINAL)
        परत 0;
    ret = ctx->meth.squeeze(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    परत ret;
}

/* Default version of the absorb() */
माप_प्रकार ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, स्थिरांक अचिन्हित अक्षर *inp, माप_प्रकार len)
{
    परत SHA3_absorb(ctx->A, inp, len, ctx->block_size);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
पूर्णांक ossl_sha3_final_default(KECCAK1600_CTX *ctx, अचिन्हित अक्षर *out, माप_प्रकार outlen)
{
    माप_प्रकार bsz = ctx->block_size;
    माप_प्रकार अंक = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    स_रखो(ctx->buf + अंक, 0, bsz - अंक);
    ctx->buf[अंक] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (शून्य)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, out, outlen, bsz, 0);
    परत 1;
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
पूर्णांक ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, अचिन्हित अक्षर *out, माप_प्रकार outlen)
{
    माप_प्रकार bsz = ctx->block_size;
    माप_प्रकार अंक = ctx->bufsz;
    माप_प्रकार len;
    पूर्णांक next = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    जर (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        स_रखो(ctx->buf + अंक, 0, bsz - अंक);
        ctx->buf[अंक] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (शून्य)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        अंक = ctx->bufsz = 0;
        next = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    जर (अंक != 0) {
        जर (outlen > ctx->bufsz)
            len = ctx->bufsz;
        अन्यथा
            len = outlen;
        स_नकल(out, ctx->buf + bsz - ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    जर (outlen == 0)
        परत 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    जर (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, out, len, bsz, next);
        next = 1;
        out += len;
        outlen -= len;
    }
    जर (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, next);
        स_नकल(out, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    परत 1;
}

स्थिर PROV_SHA3_METHOD shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#जर defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
स्थिर माप_प्रकार sha3_absorb_s390x(KECCAK1600_CTX *ctx, स्थिरांक अचिन्हित अक्षर *inp, माप_प्रकार len)
{
    माप_प्रकार rem = len % ctx->block_size;
    अचिन्हित पूर्णांक fc;

    जर (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    परत rem;
}

स्थिर पूर्णांक shake_final_s390x(KECCAK1600_CTX *ctx, अचिन्हित अक्षर *out, माप_प्रकार outlen)
{
    अचिन्हित पूर्णांक fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
    परत 1;
}

स्थिर पूर्णांक shake_squeeze_s390x(KECCAK1600_CTX *ctx, अचिन्हित अक्षर *out, माप_प्रकार outlen)
{
    अचिन्हित पूर्णांक fc;
    माप_प्रकार len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    जर (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->block_size;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        परत 1;
    }
    जर (ctx->bufsz != 0) {
        len = ctx->block_size - ctx->bufsz;
        जर (outlen < len)
            len = outlen;
        स_नकल(out, (अक्षर *)ctx->A + ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz += len;
        जर (ctx->bufsz == ctx->block_size)
            ctx->bufsz = 0;
    }
    जर (outlen == 0)
        परत 1;
    s390x_klmd(रिक्त, 0, out, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->block_size;

    परत 1;
}

स्थिर PROV_SHA3_METHOD shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#किंवाजर defined(__aarch64__) && defined(KECCAK1600_ASM)

माप_प्रकार SHA3_absorb_cext(uint64_t A[5][5], स्थिरांक अचिन्हित अक्षर *inp, माप_प्रकार len,
    माप_प्रकार r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
स्थिर माप_प्रकार sha3_absorb_arm(KECCAK1600_CTX *ctx, स्थिरांक अचिन्हित अक्षर *inp, माप_प्रकार len)
{
    परत SHA3_absorb_cext(ctx->A, inp, len, ctx->block_size);
}

स्थिर PROV_SHA3_METHOD shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#endif

KECCAK1600_CTX *ossl_shake256_new(शून्य)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(आकार(*ctx));

    जर (ctx == रिक्त)
        परत रिक्त;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_size = SIZE_MAX;
    ctx->meth = shake_generic_meth;
#जर defined(S390_SHA3)
    जर (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#किंवाजर defined(__aarch64__) && defined(KECCAK1600_ASM)
    जर (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#endif
    परत ctx;
}
