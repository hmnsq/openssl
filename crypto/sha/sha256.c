/*
 * Copyright 2004-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * SHA256 low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#ಅನ್ತರ್ಭಾವ "internal/deprecated.h"

#ಅನ್ತರ್ಭಾವ <openssl/opensslconf.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಅನ್ತರ್ಭಾವ <openssl/sha.h>
#ಅನ್ತರ್ಭಾವ <openssl/opensslv.h>
#ಅನ್ತರ್ಭಾವ "internal/endian.h"
#ಅನ್ತರ್ಭಾವ "crypto/sha.h"

ಪೂರ್ಣಾಂಕ SHA224_Init(SHA256_CTX *c)
{
    memset(c, 0, ಗಾತ್ರ(*c));
    c->h[0] = 0xc1059ed8UL;
    c->h[1] = 0x367cd507UL;
    c->h[2] = 0x3070dd17UL;
    c->h[3] = 0xf70e5939UL;
    c->h[4] = 0xffc00b31UL;
    c->h[5] = 0x68581511UL;
    c->h[6] = 0x64f98fa7UL;
    c->h[7] = 0xbefa4fa4UL;
    c->md_len = SHA224_DIGEST_ಉದ್ದಳತೆ;
    ಹಿಂತಿರುಗಿ 1;
}

ಪೂರ್ಣಾಂಕ SHA256_Init(SHA256_CTX *c)
{
    memset(c, 0, ಗಾತ್ರ(*c));
    c->h[0] = 0x6a09e667UL;
    c->h[1] = 0xbb67ae85UL;
    c->h[2] = 0x3c6ef372UL;
    c->h[3] = 0xa54ff53aUL;
    c->h[4] = 0x510e527fUL;
    c->h[5] = 0x9b05688cUL;
    c->h[6] = 0x1f83d9abUL;
    c->h[7] = 0x5be0cd19UL;
    c->md_len = SHA256_DIGEST_ಉದ್ದಳತೆ;
    ಹಿಂತಿರುಗಿ 1;
}

ಪೂರ್ಣಾಂಕ ossl_sha256_192_init(SHA256_CTX *c)
{
    SHA256_Init(c);
    c->md_len = SHA256_192_DIGEST_ಉದ್ದಳತೆ;
    ಹಿಂತಿರುಗಿ 1;
}

ಪೂರ್ಣಾಂಕ SHA224_Update(SHA256_CTX *c, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ದತ್ತಾಂಶ, size_t len)
{
    ಹಿಂತಿರುಗಿ SHA256_Update(c, ದತ್ತಾಂಶ, len);
}

ಪೂರ್ಣಾಂಕ SHA224_Final(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *md, SHA256_CTX *c)
{
    ಹಿಂತಿರುಗಿ SHA256_Final(md, c);
}

#ವ್ಯಾಖ್ಯಾನಿಸು ದತ್ತಾಂಶ_ಕ್ರಮ_IS_BIG_ENDIAN

#ವ್ಯಾಖ್ಯಾನಿಸು HASH_LONG SHA_LONG
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_CTX SHA256_CTX
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_CBLOCK SHA_CBLOCK

/*
 * Note that FIPS180-2 discusses "Truncation of the Hash Function Output."
 * default: case below covers for it. It's not clear however if it's
 * permitted to truncate to amount of bytes not divisible by 4. I bet not,
 * but if it is, then default: case shall be extended. For reference.
 * Idea behind separate cases for pre-defined lengths is to let the
 * compiler decide if it's appropriate to unroll small loops.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_MAKE_STRING(c, s)                                      \
    ಮಾಡು {                                                            \
        ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ll;                                           \
        ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ nn;                                            \
        ಆಯ್ಕೆ ((c)->md_len) {                                      \
        ಸ್ಥಿತಿ SHA256_192_DIGEST_ಉದ್ದಳತೆ:                              \
            ಗಾಗಿ (nn = 0; nn < SHA256_192_DIGEST_ಉದ್ದಳತೆ / 4; nn++) { \
                ll = (c)->h[nn];                                    \
                (ಶೂನ್ಯ)HOST_l2c(ll, (s));                            \
            }                                                       \
            ನಿಲ್ಲಿಸು;                                                  \
        ಸ್ಥಿತಿ SHA224_DIGEST_ಉದ್ದಳತೆ:                                  \
            ಗಾಗಿ (nn = 0; nn < SHA224_DIGEST_ಉದ್ದಳತೆ / 4; nn++) {     \
                ll = (c)->h[nn];                                    \
                (ಶೂನ್ಯ)HOST_l2c(ll, (s));                            \
            }                                                       \
            ನಿಲ್ಲಿಸು;                                                  \
        ಸ್ಥಿತಿ SHA256_DIGEST_ಉದ್ದಳತೆ:                                  \
            ಗಾಗಿ (nn = 0; nn < SHA256_DIGEST_ಉದ್ದಳತೆ / 4; nn++) {     \
                ll = (c)->h[nn];                                    \
                (ಶೂನ್ಯ)HOST_l2c(ll, (s));                            \
            }                                                       \
            ನಿಲ್ಲಿಸು;                                                  \
        ಪೂರ್ವನಿಯೋಜಿತ:                                                    \
            ಆದರೆ ((c)->md_len > SHA256_DIGEST_ಉದ್ದಳತೆ)                 \
                ಹಿಂತಿರುಗಿ 0;                                           \
            ಗಾಗಿ (nn = 0; nn < (c)->md_len / 4; nn++) {              \
                ll = (c)->h[nn];                                    \
                (ಶೂನ್ಯ)HOST_l2c(ll, (s));                            \
            }                                                       \
            ನಿಲ್ಲಿಸು;                                                  \
        }                                                           \
    } ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು HASH_UPDATE_THUNK
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_UPDATE SHA256_Update_thunk
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_TRANSFORM SHA256_Transform
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_FINAL SHA256_Final
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SHA256_ASM
ಸ್ಥಿರ
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ INCLUDE_C_SHA256
ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_c(SHA256_CTX *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);
#ಆದರೆ_ಅಂತ್ಯ /* INCLUDE_C_SHA256 */
#ಆದರೆ_ಅಂತ್ಯ /* SHA256_ASM */
    ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(SHA256_CTX *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);

/* clang-format off */
#ಅನ್ತರ್ಭಾವ "crypto/md32_common.inc"
/* clang-format on */
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು HASH_UPDATE_THUNK

ಪೂರ್ಣಾಂಕ SHA256_Update(SHA256_CTX *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ದತ್ತಾಂಶ, size_t sz)
{
    ಹಿಂತಿರುಗಿ SHA256_Update_thunk((ಶೂನ್ಯ *)ctx, (ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *)ದತ್ತಾಂಶ, sz);
}

#ಆದರೆ !defined(SHA256_ASM) || defined(INCLUDE_C_SHA256)
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ SHA_LONG K256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ PEDANTIC
#ಆದರೆ defined(__GNUC__) && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
#ಆದರೆ defined(__riscv_zknh)
#ವ್ಯಾಖ್ಯಾನಿಸು Sigma0(x) ({ MD32_REG_T ret;            \
                        asm ("sha256sum0 %0, %1"    \
                        : "=r"(ret)                 \
                        : "r"(x)); ret; })
#ವ್ಯಾಖ್ಯಾನಿಸು Sigma1(x) ({ MD32_REG_T ret;            \
                        asm ("sha256sum1 %0, %1"    \
                        : "=r"(ret)                 \
                        : "r"(x)); ret; })
#ವ್ಯಾಖ್ಯಾನಿಸು sigma0(x) ({ MD32_REG_T ret;            \
                        asm ("sha256sig0 %0, %1"    \
                        : "=r"(ret)                 \
                        : "r"(x)); ret; })
#ವ್ಯಾಖ್ಯಾನಿಸು sigma1(x) ({ MD32_REG_T ret;            \
                        asm ("sha256sig1 %0, %1"    \
                        : "=r"(ret)                 \
                        : "r"(x)); ret; })
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(__riscv_zbt) || defined(__riscv_zpn)
#ವ್ಯಾಖ್ಯಾನಿಸು Ch(x, y, z) ({  MD32_REG_T ret;                           \
                        asm (".insn r4 0x33, 1, 0x3, %0, %2, %1, %3"\
                        : "=r"(ret)                                 \
                        : "r"(x), "r"(y), "r"(z)); ret; })
#ವ್ಯಾಖ್ಯಾನಿಸು Maj(x, y, z) ({ MD32_REG_T ret;                           \
                        asm (".insn r4 0x33, 1, 0x3, %0, %2, %1, %3"\
                        : "=r"(ret)                                 \
                        : "r"(x^z), "r"(y), "r"(x)); ret; })
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ

/*
 * FIPS specification refers to right rotations, while our ROTATE macro
 * is left one. This is why you might notice that rotation coefficients
 * differ from those observed in FIPS document by 32-N...
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ Sigma0
#ವ್ಯಾಖ್ಯಾನಿಸು Sigma0(x) (ROTATE((x), 30) ^ ROTATE((x), 19) ^ ROTATE((x), 10))
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ Sigma1
#ವ್ಯಾಖ್ಯಾನಿಸು Sigma1(x) (ROTATE((x), 26) ^ ROTATE((x), 21) ^ ROTATE((x), 7))
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ sigma0
#ವ್ಯಾಖ್ಯಾನಿಸು sigma0(x) (ROTATE((x), 25) ^ ROTATE((x), 14) ^ ((x) >> 3))
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ sigma1
#ವ್ಯಾಖ್ಯಾನಿಸು sigma1(x) (ROTATE((x), 15) ^ ROTATE((x), 13) ^ ((x) >> 10))
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ Ch
#ವ್ಯಾಖ್ಯಾನಿಸು Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ Maj
#ವ್ಯಾಖ್ಯಾನಿಸು Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ OPENSSL_SMALL_FOOTPRINT

ಸ್ಥಿರ ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(SHA256_CTX *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ,
    size_t ಅಂಕೆ)
{
    ಚಿಹ್ನೆರಹಿತ MD32_REG_T a, b, c, d, e, f, g, h, s0, s1, T1, T2;
    SHA_LONG X[16], l;
    ಪೂರ್ಣಾಂಕ i;
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ = ಒಳ;

    ಆಗ (ಅಂಕೆ--) {

        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];

        ಗಾಗಿ (i = 0; i < 16; i++) {
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[i] = l;
            T1 += h + Sigma1(e) + Ch(e, f, g) + K256[i];
            T2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        ಗಾಗಿ (; i < 64; i++) {
            s0 = X[(i + 1) & 0x0f];
            s0 = sigma0(s0);
            s1 = X[(i + 14) & 0x0f];
            s1 = sigma1(s1);

            T1 = X[i & 0xf] += s0 + s1 + X[(i + 9) & 0xf];
            T1 += h + Sigma1(e) + Ch(e, f, g) + K256[i];
            T2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        ctx->h[0] += a;
        ctx->h[1] += b;
        ctx->h[2] += c;
        ctx->h[3] += d;
        ctx->h[4] += e;
        ctx->h[5] += f;
        ctx->h[6] += g;
        ctx->h[7] += h;
    }
}

#ಇಲ್ಲದಿದ್ದರೆ

#ವ್ಯಾಖ್ಯಾನಿಸು ಸುತ್ತು_00_15(i, a, b, c, d, e, f, g, h)       \
    ಮಾಡು {                                             \
        T1 += h + Sigma1(e) + Ch(e, f, g) + K256[i]; \
        h = Sigma0(a) + Maj(a, b, c);                \
        d += T1;                                     \
        h += T1;                                     \
    } ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು ಸುತ್ತು_16_63(i, a, b, c, d, e, f, g, h, X)          \
    ಮಾಡು {                                                   \
        s0 = X[(i + 1) & 0x0f];                            \
        s0 = sigma0(s0);                                   \
        s1 = X[(i + 14) & 0x0f];                           \
        s1 = sigma1(s1);                                   \
        T1 = X[(i) & 0x0f] += s0 + s1 + X[(i + 9) & 0x0f]; \
        ಸುತ್ತು_00_15(i, a, b, c, d, e, f, g, h);            \
    } ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ INCLUDE_C_SHA256
ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_c(SHA256_CTX *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ)
#ಇಲ್ಲದಿದ್ದರೆ
ಸ್ಥಿರ ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(SHA256_CTX *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ,
    size_t ಅಂಕೆ)
#ಆದರೆ_ಅಂತ್ಯ
{
    ಚಿಹ್ನೆರಹಿತ MD32_REG_T a, b, c, d, e, f, g, h, s0, s1, T1;
    SHA_LONG X[16];
    ಪೂರ್ಣಾಂಕ i;
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ = ಒಳ;
    DECLARE_IS_ENDIAN;

    ಆಗ (ಅಂಕೆ--) {

        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];

        ಆದರೆ (!IS_LITTLE_ENDIAN && ಗಾತ್ರ(SHA_LONG) == 4
            && ((size_t)ಒಳ % 4) == 0) {
            ಸ್ಥಿರಾಂಕ SHA_LONG *W = (ಸ್ಥಿರಾಂಕ SHA_LONG *)ದತ್ತಾಂಶ;

            T1 = X[0] = W[0];
            ಸುತ್ತು_00_15(0, a, b, c, d, e, f, g, h);
            T1 = X[1] = W[1];
            ಸುತ್ತು_00_15(1, h, a, b, c, d, e, f, g);
            T1 = X[2] = W[2];
            ಸುತ್ತು_00_15(2, g, h, a, b, c, d, e, f);
            T1 = X[3] = W[3];
            ಸುತ್ತು_00_15(3, f, g, h, a, b, c, d, e);
            T1 = X[4] = W[4];
            ಸುತ್ತು_00_15(4, e, f, g, h, a, b, c, d);
            T1 = X[5] = W[5];
            ಸುತ್ತು_00_15(5, d, e, f, g, h, a, b, c);
            T1 = X[6] = W[6];
            ಸುತ್ತು_00_15(6, c, d, e, f, g, h, a, b);
            T1 = X[7] = W[7];
            ಸುತ್ತು_00_15(7, b, c, d, e, f, g, h, a);
            T1 = X[8] = W[8];
            ಸುತ್ತು_00_15(8, a, b, c, d, e, f, g, h);
            T1 = X[9] = W[9];
            ಸುತ್ತು_00_15(9, h, a, b, c, d, e, f, g);
            T1 = X[10] = W[10];
            ಸುತ್ತು_00_15(10, g, h, a, b, c, d, e, f);
            T1 = X[11] = W[11];
            ಸುತ್ತು_00_15(11, f, g, h, a, b, c, d, e);
            T1 = X[12] = W[12];
            ಸುತ್ತು_00_15(12, e, f, g, h, a, b, c, d);
            T1 = X[13] = W[13];
            ಸುತ್ತು_00_15(13, d, e, f, g, h, a, b, c);
            T1 = X[14] = W[14];
            ಸುತ್ತು_00_15(14, c, d, e, f, g, h, a, b);
            T1 = X[15] = W[15];
            ಸುತ್ತು_00_15(15, b, c, d, e, f, g, h, a);

            ದತ್ತಾಂಶ += SHA256_CBLOCK;
        } ಇಲ್ಲದಿದ್ದರೆ {
            SHA_LONG l;

            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[0] = l;
            ಸುತ್ತು_00_15(0, a, b, c, d, e, f, g, h);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[1] = l;
            ಸುತ್ತು_00_15(1, h, a, b, c, d, e, f, g);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[2] = l;
            ಸುತ್ತು_00_15(2, g, h, a, b, c, d, e, f);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[3] = l;
            ಸುತ್ತು_00_15(3, f, g, h, a, b, c, d, e);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[4] = l;
            ಸುತ್ತು_00_15(4, e, f, g, h, a, b, c, d);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[5] = l;
            ಸುತ್ತು_00_15(5, d, e, f, g, h, a, b, c);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[6] = l;
            ಸುತ್ತು_00_15(6, c, d, e, f, g, h, a, b);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[7] = l;
            ಸುತ್ತು_00_15(7, b, c, d, e, f, g, h, a);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[8] = l;
            ಸುತ್ತು_00_15(8, a, b, c, d, e, f, g, h);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[9] = l;
            ಸುತ್ತು_00_15(9, h, a, b, c, d, e, f, g);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[10] = l;
            ಸುತ್ತು_00_15(10, g, h, a, b, c, d, e, f);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[11] = l;
            ಸುತ್ತು_00_15(11, f, g, h, a, b, c, d, e);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[12] = l;
            ಸುತ್ತು_00_15(12, e, f, g, h, a, b, c, d);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[13] = l;
            ಸುತ್ತು_00_15(13, d, e, f, g, h, a, b, c);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[14] = l;
            ಸುತ್ತು_00_15(14, c, d, e, f, g, h, a, b);
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            T1 = X[15] = l;
            ಸುತ್ತು_00_15(15, b, c, d, e, f, g, h, a);
        }

        ಗಾಗಿ (i = 16; i < 64; i += 8) {
            ಸುತ್ತು_16_63(i + 0, a, b, c, d, e, f, g, h, X);
            ಸುತ್ತು_16_63(i + 1, h, a, b, c, d, e, f, g, X);
            ಸುತ್ತು_16_63(i + 2, g, h, a, b, c, d, e, f, X);
            ಸುತ್ತು_16_63(i + 3, f, g, h, a, b, c, d, e, X);
            ಸುತ್ತು_16_63(i + 4, e, f, g, h, a, b, c, d, X);
            ಸುತ್ತು_16_63(i + 5, d, e, f, g, h, a, b, c, X);
            ಸುತ್ತು_16_63(i + 6, c, d, e, f, g, h, a, b, X);
            ಸುತ್ತು_16_63(i + 7, b, c, d, e, f, g, h, a, X);
        }

        ctx->h[0] += a;
        ctx->h[1] += b;
        ctx->h[2] += c;
        ctx->h[3] += d;
        ctx->h[4] += e;
        ctx->h[5] += f;
        ctx->h[6] += g;
        ctx->h[7] += h;
    }
}

#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ /* SHA256_ASM */
