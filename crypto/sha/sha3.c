/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#समावेश <string.h>
#समावेश "internal/sha3.h"
#समावेश "internal/common.h"

#अगर defined(__aarch64__) && defined(KECCAK1600_ASM)
#समावेश "arch/arm_arch.h"
#पूर्ण_अगर

#अगर defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#समावेश "arch/s390x_arch.h"
#अगर defined(KECCAK1600_ASM)
#घोषणा S390_SHA3 1
#घोषणा S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#पूर्ण_अगर
#पूर्ण_अगर

व्योम SHA3_squeeze(uint64_t A[5][5], अचिन्हित अक्षर *out, माप_प्रकार len, माप_प्रकार r, पूर्णांक अग्र);

व्योम ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#अगर defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    अगर (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#पूर्ण_अगर
        स_रखो(ctx->A, 0, माप(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

पूर्णांक ossl_sha3_init(KECCAK1600_CTX *ctx, अचिन्हित अक्षर pad, माप_प्रकार bitlen)
{
    माप_प्रकार bsz = SHA3_BLOCKSIZE(bitlen);

    अगर (bsz <= माप(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->block_आकार = bsz;
        ctx->md_आकार = bitlen / 8;
        ctx->pad = pad;
        वापस 1;
    }

    वापस 0;
}

पूर्णांक ossl_keccak_init(KECCAK1600_CTX *ctx, अचिन्हित अक्षर pad, माप_प्रकार bitlen, माप_प्रकार mdlen)
{
    पूर्णांक ret = ossl_sha3_init(ctx, pad, bitlen);

    अगर (ret)
        ctx->md_आकार = mdlen / 8;
    वापस ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
पूर्णांक ossl_sha3_absorb(KECCAK1600_CTX *ctx, स्थिर अचिन्हित अक्षर *inp, माप_प्रकार len)
{
    स्थिर माप_प्रकार bsz = ctx->block_आकार;
    माप_प्रकार अंक, rem;

    अगर (ossl_unlikely(len == 0))
        वापस 1;

    अगर (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        वापस 0;

    /* Is there anything in the buffer already ? */
    अगर ((अंक = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - अंक;
        /* If the new input does not fill the buffer then just add it */
        अगर (len < rem) {
            स_नकल(ctx->buf + अंक, inp, len);
            ctx->bufsz += len;
            वापस 1;
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
    अगर (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    अगर (ossl_likely(rem > 0)) {
        स_नकल(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    वापस 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
पूर्णांक ossl_sha3_final(KECCAK1600_CTX *ctx, अचिन्हित अक्षर *out, माप_प्रकार outlen)
{
    पूर्णांक ret;

    अगर (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        वापस 0;
    अगर (outlen == 0)
        वापस 1;

    ret = ctx->meth.final(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    वापस ret;
}

/* Calls a platform specific squeeze method */
पूर्णांक ossl_sha3_squeeze(KECCAK1600_CTX *ctx, अचिन्हित अक्षर *out, माप_प्रकार outlen)
{
    पूर्णांक ret = 0;

    अगर (ctx->xof_state == XOF_STATE_FINAL)
        वापस 0;
    ret = ctx->meth.squeeze(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    वापस ret;
}

/* Default version of the absorb() */
माप_प्रकार ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, स्थिर अचिन्हित अक्षर *inp, माप_प्रकार len)
{
    वापस SHA3_absorb(ctx->A, inp, len, ctx->block_आकार);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
पूर्णांक ossl_sha3_final_default(KECCAK1600_CTX *ctx, अचिन्हित अक्षर *out, माप_प्रकार outlen)
{
    माप_प्रकार bsz = ctx->block_आकार;
    माप_प्रकार अंक = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    स_रखो(ctx->buf + अंक, 0, bsz - अंक);
    ctx->buf[अंक] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (व्योम)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, out, outlen, bsz, 0);
    वापस 1;
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
    माप_प्रकार bsz = ctx->block_आकार;
    माप_प्रकार अंक = ctx->bufsz;
    माप_प्रकार len;
    पूर्णांक अग्र = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    अगर (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        स_रखो(ctx->buf + अंक, 0, bsz - अंक);
        ctx->buf[अंक] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (व्योम)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        अंक = ctx->bufsz = 0;
        अग्र = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    अगर (अंक != 0) {
        अगर (outlen > ctx->bufsz)
            len = ctx->bufsz;
        अन्यथा
            len = outlen;
        स_नकल(out, ctx->buf + bsz - ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    अगर (outlen == 0)
        वापस 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    अगर (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, out, len, bsz, अग्र);
        अग्र = 1;
        out += len;
        outlen -= len;
    }
    अगर (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, अग्र);
        स_नकल(out, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    वापस 1;
}

अटल PROV_SHA3_METHOD shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#अगर defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
अटल माप_प्रकार sha3_absorb_s390x(KECCAK1600_CTX *ctx, स्थिर अचिन्हित अक्षर *inp, माप_प्रकार len)
{
    माप_प्रकार rem = len % ctx->block_आकार;
    अचिन्हित पूर्णांक fc;

    अगर (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    वापस rem;
}

अटल पूर्णांक shake_final_s390x(KECCAK1600_CTX *ctx, अचिन्हित अक्षर *out, माप_प्रकार outlen)
{
    अचिन्हित पूर्णांक fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
    वापस 1;
}

अटल पूर्णांक shake_squeeze_s390x(KECCAK1600_CTX *ctx, अचिन्हित अक्षर *out, माप_प्रकार outlen)
{
    अचिन्हित पूर्णांक fc;
    माप_प्रकार len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    अगर (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->block_आकार;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        वापस 1;
    }
    अगर (ctx->bufsz != 0) {
        len = ctx->block_आकार - ctx->bufsz;
        अगर (outlen < len)
            len = outlen;
        स_नकल(out, (अक्षर *)ctx->A + ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz += len;
        अगर (ctx->bufsz == ctx->block_आकार)
            ctx->bufsz = 0;
    }
    अगर (outlen == 0)
        वापस 1;
    s390x_klmd(शून्य, 0, out, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->block_आकार;

    वापस 1;
}

अटल PROV_SHA3_METHOD shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#या_अगर defined(__aarch64__) && defined(KECCAK1600_ASM)

माप_प्रकार SHA3_absorb_cext(uint64_t A[5][5], स्थिर अचिन्हित अक्षर *inp, माप_प्रकार len,
    माप_प्रकार r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
अटल माप_प्रकार sha3_absorb_arm(KECCAK1600_CTX *ctx, स्थिर अचिन्हित अक्षर *inp, माप_प्रकार len)
{
    वापस SHA3_absorb_cext(ctx->A, inp, len, ctx->block_आकार);
}

अटल PROV_SHA3_METHOD shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#पूर्ण_अगर

KECCAK1600_CTX *ossl_shake256_new(व्योम)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(माप(*ctx));

    अगर (ctx == शून्य)
        वापस शून्य;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_आकार = आकार_MAX;
    ctx->meth = shake_generic_meth;
#अगर defined(S390_SHA3)
    अगर (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#या_अगर defined(__aarch64__) && defined(KECCAK1600_ASM)
    अगर (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#पूर्ण_अगर
    वापस ctx;
}
