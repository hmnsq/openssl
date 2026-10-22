/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ "internal/sha3.h"
#അന്തര്ഭാവ "internal/common.h"

#എങ്കിൽ defined(__aarch64__) && defined(KECCAK1600_ASM)
#അന്തര്ഭാവ "arch/arm_arch.h"
#endif

#എങ്കിൽ defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
#അന്തര്ഭാവ "arch/s390x_arch.h"
#എങ്കിൽ defined(KECCAK1600_ASM)
#define S390_SHA3 1
#define S390_SHA3_CAPABLE(name) \
    ((OPENSSL_s390xcap_P.kimd[0] & S390X_CAPBIT(name)) && (OPENSSL_s390xcap_P.klmd[0] & S390X_CAPBIT(name)))
#endif
#endif

ശൂന്യം SHA3_squeeze(uint64_t A[5][5], unsigned അക്ഷരം *out, size_t len, size_t r, പൂർണ്ണസംഖ്യ next);

ശൂന്യം ossl_sha3_reset(KECCAK1600_CTX *ctx)
{
#എങ്കിൽ defined(__s390x__) && defined(OPENSSL_CPUID_OBJ)
    എങ്കിൽ (!(OPENSSL_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA12)))
#endif
        memset(ctx->A, 0, വലുപ്പം(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

പൂർണ്ണസംഖ്യ ossl_sha3_init(KECCAK1600_CTX *ctx, unsigned അക്ഷരം pad, size_t bitlen)
{
    size_t bsz = SHA3_BLOCKSIZE(bitlen);

    എങ്കിൽ (bsz <= വലുപ്പം(ctx->buf)) {
        ossl_sha3_reset(ctx);
        ctx->block_size = bsz;
        ctx->md_size = bitlen / 8;
        ctx->pad = pad;
        തിരികെ 1;
    }

    തിരികെ 0;
}

പൂർണ്ണസംഖ്യ ossl_keccak_init(KECCAK1600_CTX *ctx, unsigned അക്ഷരം pad, size_t bitlen, size_t mdlen)
{
    പൂർണ്ണസംഖ്യ ret = ossl_sha3_init(ctx, pad, bitlen);

    എങ്കിൽ (ret)
        ctx->md_size = mdlen / 8;
    തിരികെ ret;
}

/*
 * A buffered absorb function that calls a platform specific absorb
 * method.
 */
പൂർണ്ണസംഖ്യ ossl_sha3_absorb(KECCAK1600_CTX *ctx, സ്ഥിരം unsigned അക്ഷരം *inp, size_t len)
{
    സ്ഥിരം size_t bsz = ctx->block_size;
    size_t അക്കം, rem;

    എങ്കിൽ (ossl_unlikely(len == 0))
        തിരികെ 1;

    എങ്കിൽ (!(ctx->xof_state == XOF_STATE_INIT || ctx->xof_state == XOF_STATE_ABSORB))
        തിരികെ 0;

    /* Is there anything in the buffer already ? */
    എങ്കിൽ ((അക്കം = ctx->bufsz) != 0) {
        /* Calculate how much space is left in the buffer */
        rem = bsz - അക്കം;
        /* If the new input does not fill the buffer then just add it */
        എങ്കിൽ (len < rem) {
            memcpy(ctx->buf + അക്കം, inp, len);
            ctx->bufsz += len;
            തിരികെ 1;
        }
        /* otherwise fill up the buffer and absorb the buffer */
        memcpy(ctx->buf + അക്കം, inp, rem);
        /* Update the input pointer */
        inp += rem;
        len -= rem;
        ctx->meth.absorb(ctx, ctx->buf, bsz);
        ctx->bufsz = 0;
        ctx->xof_state = XOF_STATE_ABSORB;
    }
    /* Absorb the input - rem = leftover part of the input < blocksize) */
    rem = ctx->meth.absorb(ctx, inp, len);
    എങ്കിൽ (len >= bsz)
        ctx->xof_state = XOF_STATE_ABSORB;
    /* Copy the leftover bit of the input into the buffer */
    എങ്കിൽ (ossl_likely(rem > 0)) {
        memcpy(ctx->buf, inp + len - rem, rem);
        ctx->bufsz = rem;
    }
    തിരികെ 1;
}

/*
 * Call a platform specific final method.
 * In most cases outlen should be set to ctx->mdlen.
 * This function assumes the caller has checked outlen is bounded.
 */
പൂർണ്ണസംഖ്യ ossl_sha3_final(KECCAK1600_CTX *ctx, unsigned അക്ഷരം *out, size_t outlen)
{
    പൂർണ്ണസംഖ്യ ret;

    എങ്കിൽ (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
        തിരികെ 0;
    എങ്കിൽ (outlen == 0)
        തിരികെ 1;

    ret = ctx->meth.final(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_FINAL;
    തിരികെ ret;
}

/* Calls a platform specific squeeze method */
പൂർണ്ണസംഖ്യ ossl_sha3_squeeze(KECCAK1600_CTX *ctx, unsigned അക്ഷരം *out, size_t outlen)
{
    പൂർണ്ണസംഖ്യ ret = 0;

    എങ്കിൽ (ctx->xof_state == XOF_STATE_FINAL)
        തിരികെ 0;
    ret = ctx->meth.squeeze(ctx, out, outlen);
    ctx->xof_state = XOF_STATE_SQUEEZE;
    തിരികെ ret;
}

/* Default version of the absorb() */
size_t ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, സ്ഥിരം unsigned അക്ഷരം *inp, size_t len)
{
    തിരികെ SHA3_absorb(ctx->A, inp, len, ctx->block_size);
}

/*
 * Default version of the final() is a single shot method
 * (Use ossl_sha3_default_squeeze() for multiple calls).
 */
പൂർണ്ണസംഖ്യ ossl_sha3_final_default(KECCAK1600_CTX *ctx, unsigned അക്ഷരം *out, size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t അക്കം = ctx->bufsz;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + അക്കം, 0, bsz - അക്കം);
    ctx->buf[അക്കം] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (ശൂന്യം)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, out, outlen, bsz, 0);
    തിരികെ 1;
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
പൂർണ്ണസംഖ്യ ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, unsigned അക്ഷരം *out, size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t അക്കം = ctx->bufsz;
    size_t len;
    പൂർണ്ണസംഖ്യ next = 1;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    എങ്കിൽ (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + അക്കം, 0, bsz - അക്കം);
        ctx->buf[അക്കം] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (ശൂന്യം)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        അക്കം = ctx->bufsz = 0;
        next = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    എങ്കിൽ (അക്കം != 0) {
        എങ്കിൽ (outlen > ctx->bufsz)
            len = ctx->bufsz;
        അല്ലെങ്കിൽ
            len = outlen;
        memcpy(out, ctx->buf + bsz - ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    എങ്കിൽ (outlen == 0)
        തിരികെ 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    എങ്കിൽ (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_squeeze(ctx->A, out, len, bsz, next);
        next = 1;
        out += len;
        outlen -= len;
    }
    എങ്കിൽ (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_squeeze(ctx->A, ctx->buf, bsz, bsz, next);
        memcpy(out, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->bufsz = bsz - outlen;
    }
    തിരികെ 1;
}

സ്ഥിതം PROV_SHA3_METHOD shake_generic_meth = {
    ossl_sha3_absorb_default,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};

#എങ്കിൽ defined(S390_SHA3)

/*-
 * The platform specific parts of the absorb() and final() for S390X.
 */
സ്ഥിതം size_t sha3_absorb_s390x(KECCAK1600_CTX *ctx, സ്ഥിരം unsigned അക്ഷരം *inp, size_t len)
{
    size_t rem = len % ctx->block_size;
    unsigned പൂർണ്ണസംഖ്യ fc;

    എങ്കിൽ (len - rem > 0) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KIMD_NIP : 0;
        s390x_kimd(inp, len - rem, fc, ctx->A);
    }
    തിരികെ rem;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ shake_final_s390x(KECCAK1600_CTX *ctx, unsigned അക്ഷരം *out, size_t outlen)
{
    unsigned പൂർണ്ണസംഖ്യ fc;

    fc = ctx->pad | S390X_KLMD_DUFOP;
    fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
    s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
    തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ shake_squeeze_s390x(KECCAK1600_CTX *ctx, unsigned അക്ഷരം *out, size_t outlen)
{
    unsigned പൂർണ്ണസംഖ്യ fc;
    size_t len;

    /*
     * On the first squeeze call, finish the absorb process (incl. padding).
     */
    എങ്കിൽ (ctx->xof_state != XOF_STATE_SQUEEZE) {
        fc = ctx->pad;
        fc |= ctx->xof_state == XOF_STATE_INIT ? S390X_KLMD_NIP : 0;
        s390x_klmd(ctx->buf, ctx->bufsz, out, outlen, fc, ctx->A);
        ctx->bufsz = outlen % ctx->block_size;
        /* reuse ctx->bufsz to count bytes squeezed from current sponge */
        തിരികെ 1;
    }
    എങ്കിൽ (ctx->bufsz != 0) {
        len = ctx->block_size - ctx->bufsz;
        എങ്കിൽ (outlen < len)
            len = outlen;
        memcpy(out, (അക്ഷരം *)ctx->A + ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz += len;
        എങ്കിൽ (ctx->bufsz == ctx->block_size)
            ctx->bufsz = 0;
    }
    എങ്കിൽ (outlen == 0)
        തിരികെ 1;
    s390x_klmd(ശൂന്യ, 0, out, outlen, ctx->pad | S390X_KLMD_PS, ctx->A);
    ctx->bufsz = outlen % ctx->block_size;

    തിരികെ 1;
}

സ്ഥിതം PROV_SHA3_METHOD shake_s390x_meth = {
    sha3_absorb_s390x,
    shake_final_s390x,
    shake_squeeze_s390x
};
#അല്ലെങ്കിലെങ്കിൽ defined(__aarch64__) && defined(KECCAK1600_ASM)

size_t SHA3_absorb_cext(uint64_t A[5][5], സ്ഥിരം unsigned അക്ഷരം *inp, size_t len,
    size_t r);
/*-
 * Hardware-assisted ARMv8.2 SHA3 extension version of the absorb()
 */
സ്ഥിതം size_t sha3_absorb_arm(KECCAK1600_CTX *ctx, സ്ഥിരം unsigned അക്ഷരം *inp, size_t len)
{
    തിരികെ SHA3_absorb_cext(ctx->A, inp, len, ctx->block_size);
}

സ്ഥിതം PROV_SHA3_METHOD shake_ARMSHA3_meth = {
    sha3_absorb_arm,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default
};
#endif

KECCAK1600_CTX *ossl_shake256_new(ശൂന്യം)
{
    KECCAK1600_CTX *ctx = OPENSSL_zalloc(വലുപ്പം(*ctx));

    എങ്കിൽ (ctx == ശൂന്യ)
        തിരികെ ശൂന്യ;
    ossl_keccak_init(ctx, '\x1f', 256, 0);
    ctx->md_size = SIZE_MAX;
    ctx->meth = shake_generic_meth;
#എങ്കിൽ defined(S390_SHA3)
    എങ്കിൽ (S390_SHA3_CAPABLE(S390X_SHAKE_256)) {
        ctx->pad = S390X_SHAKE_256;
        ctx->meth = shake_s390x_meth;
    }
#അല്ലെങ്കിലെങ്കിൽ defined(__aarch64__) && defined(KECCAK1600_ASM)
    എങ്കിൽ (OPENSSL_armcap_P & ARMV8_HAVE_SHA3_AND_WORTH_USING)
        ctx->meth = shake_ARMSHA3_meth;
#endif
    തിരികെ ctx;
}
