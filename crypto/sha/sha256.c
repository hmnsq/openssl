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
#ضمن "internal/deprecated.h"

#ضمن <openssl/opensslconf.h>

#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن <openssl/crypto.h>
#ضمن <openssl/sha.h>
#ضمن <openssl/opensslv.h>
#ضمن "internal/endian.h"
#ضمن "crypto/sha.h"

صحيح SHA224_Init(SHA256_CTX *c)
{
    memset(c, 0, حجم(*c));
    c->h[0] = 0xc1059ed8UL;
    c->h[1] = 0x367cd507UL;
    c->h[2] = 0x3070dd17UL;
    c->h[3] = 0xf70e5939UL;
    c->h[4] = 0xffc00b31UL;
    c->h[5] = 0x68581511UL;
    c->h[6] = 0x64f98fa7UL;
    c->h[7] = 0xbefa4fa4UL;
    c->md_len = SHA224_DIGEST_ڊيگهائي;
    أرجع 1;
}

صحيح SHA256_Init(SHA256_CTX *c)
{
    memset(c, 0, حجم(*c));
    c->h[0] = 0x6a09e667UL;
    c->h[1] = 0xbb67ae85UL;
    c->h[2] = 0x3c6ef372UL;
    c->h[3] = 0xa54ff53aUL;
    c->h[4] = 0x510e527fUL;
    c->h[5] = 0x9b05688cUL;
    c->h[6] = 0x1f83d9abUL;
    c->h[7] = 0x5be0cd19UL;
    c->md_len = SHA256_DIGEST_ڊيگهائي;
    أرجع 1;
}

صحيح ossl_sha256_192_init(SHA256_CTX *c)
{
    SHA256_Init(c);
    c->md_len = SHA256_192_DIGEST_ڊيگهائي;
    أرجع 1;
}

صحيح SHA224_Update(SHA256_CTX *c, ثابت فراغ *معلومات, size_t len)
{
    أرجع SHA256_Update(c, معلومات, len);
}

صحيح SHA224_Final(بنانشان حرف *md, SHA256_CTX *c)
{
    أرجع SHA256_Final(md, c);
}

#وصف_ڪريو معلومات_ترتيب_IS_BIG_ENDIAN

#وصف_ڪريو HASH_LONG SHA_LONG
#وصف_ڪريو HASH_CTX SHA256_CTX
#وصف_ڪريو HASH_CBLOCK SHA_CBLOCK

/*
 * Note that FIPS180-2 discusses "Truncation of the Hash Function Output."
 * default: case below covers for it. It's not clear however if it's
 * permitted to truncate to amount of bytes not divisible by 4. I bet not,
 * but if it is, then default: case shall be extended. For reference.
 * Idea behind separate cases for pre-defined lengths is to let the
 * compiler decide if it's appropriate to unroll small loops.
 */
#وصف_ڪريو HASH_MAKE_STRING(c, s)                                      \
    افعل {                                                            \
        بنانشان ڊگهو ll;                                           \
        بنانشان صحيح nn;                                            \
        بدل ((c)->md_len) {                                      \
        حالة SHA256_192_DIGEST_ڊيگهائي:                              \
            لكل (nn = 0; nn < SHA256_192_DIGEST_ڊيگهائي / 4; nn++) { \
                ll = (c)->h[nn];                                    \
                (فراغ)HOST_l2c(ll, (s));                            \
            }                                                       \
            اكسر;                                                  \
        حالة SHA224_DIGEST_ڊيگهائي:                                  \
            لكل (nn = 0; nn < SHA224_DIGEST_ڊيگهائي / 4; nn++) {     \
                ll = (c)->h[nn];                                    \
                (فراغ)HOST_l2c(ll, (s));                            \
            }                                                       \
            اكسر;                                                  \
        حالة SHA256_DIGEST_ڊيگهائي:                                  \
            لكل (nn = 0; nn < SHA256_DIGEST_ڊيگهائي / 4; nn++) {     \
                ll = (c)->h[nn];                                    \
                (فراغ)HOST_l2c(ll, (s));                            \
            }                                                       \
            اكسر;                                                  \
        افتراضي:                                                    \
            إذا ((c)->md_len > SHA256_DIGEST_ڊيگهائي)                 \
                أرجع 0;                                           \
            لكل (nn = 0; nn < (c)->md_len / 4; nn++) {              \
                ll = (c)->h[nn];                                    \
                (فراغ)HOST_l2c(ll, (s));                            \
            }                                                       \
            اكسر;                                                  \
        }                                                           \
    } طالما (0)

#وصف_ڪريو HASH_UPDATE_THUNK
#وصف_ڪريو HASH_UPDATE SHA256_Update_thunk
#وصف_ڪريو HASH_TRANSFORM SHA256_Transform
#وصف_ڪريو HASH_FINAL SHA256_Final
#وصف_ڪريو HASH_بلاڪ_معلومات_ترتيب sha256_بلاڪ_معلومات_ترتيب
#جيڪڏهن_وصف_نه_ٿيل SHA256_ASM
ساكن
#وإلا
#جيڪڏهن_وصف_ٿيل INCLUDE_C_SHA256
فراغ sha256_بلاڪ_معلومات_ترتيب_c(SHA256_CTX *ctx, ثابت فراغ *اندريون, size_t انگ);
#جيڪڏهن_پورو /* INCLUDE_C_SHA256 */
#جيڪڏهن_پورو /* SHA256_ASM */
    فراغ sha256_بلاڪ_معلومات_ترتيب(SHA256_CTX *ctx, ثابت فراغ *اندريون, size_t انگ);

/* clang-format off */
#ضمن "crypto/md32_common.inc"
/* clang-format on */
#وصف_رد HASH_UPDATE_THUNK

صحيح SHA256_Update(SHA256_CTX *ctx, ثابت فراغ *معلومات, size_t sz)
{
    أرجع SHA256_Update_thunk((فراغ *)ctx, (ثابت بنانشان حرف *)معلومات, sz);
}

#إذا !defined(SHA256_ASM) || defined(INCLUDE_C_SHA256)
ساكن ثابت SHA_LONG K256[64] = {
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

#جيڪڏهن_وصف_نه_ٿيل PEDANTIC
#إذا defined(__GNUC__) && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
#إذا defined(__riscv_zknh)
#وصف_ڪريو Sigma0(x) ({ MD32_REG_T ret;            \
                        asm ("sha256sum0 %0, %1"    \
                        : "=r"(ret)                 \
                        : "r"(x)); ret; })
#وصف_ڪريو Sigma1(x) ({ MD32_REG_T ret;            \
                        asm ("sha256sum1 %0, %1"    \
                        : "=r"(ret)                 \
                        : "r"(x)); ret; })
#وصف_ڪريو sigma0(x) ({ MD32_REG_T ret;            \
                        asm ("sha256sig0 %0, %1"    \
                        : "=r"(ret)                 \
                        : "r"(x)); ret; })
#وصف_ڪريو sigma1(x) ({ MD32_REG_T ret;            \
                        asm ("sha256sig1 %0, %1"    \
                        : "=r"(ret)                 \
                        : "r"(x)); ret; })
#جيڪڏهن_پورو
#إذا defined(__riscv_zbt) || defined(__riscv_zpn)
#وصف_ڪريو Ch(x, y, z) ({  MD32_REG_T ret;                           \
                        asm (".insn r4 0x33, 1, 0x3, %0, %2, %1, %3"\
                        : "=r"(ret)                                 \
                        : "r"(x), "r"(y), "r"(z)); ret; })
#وصف_ڪريو Maj(x, y, z) ({ MD32_REG_T ret;                           \
                        asm (".insn r4 0x33, 1, 0x3, %0, %2, %1, %3"\
                        : "=r"(ret)                                 \
                        : "r"(x^z), "r"(y), "r"(x)); ret; })
#جيڪڏهن_پورو
#جيڪڏهن_پورو
#جيڪڏهن_پورو

/*
 * FIPS specification refers to right rotations, while our ROTATE macro
 * is left one. This is why you might notice that rotation coefficients
 * differ from those observed in FIPS document by 32-N...
 */
#جيڪڏهن_وصف_نه_ٿيل Sigma0
#وصف_ڪريو Sigma0(x) (ROTATE((x), 30) ^ ROTATE((x), 19) ^ ROTATE((x), 10))
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل Sigma1
#وصف_ڪريو Sigma1(x) (ROTATE((x), 26) ^ ROTATE((x), 21) ^ ROTATE((x), 7))
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل sigma0
#وصف_ڪريو sigma0(x) (ROTATE((x), 25) ^ ROTATE((x), 14) ^ ((x) >> 3))
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل sigma1
#وصف_ڪريو sigma1(x) (ROTATE((x), 15) ^ ROTATE((x), 13) ^ ((x) >> 10))
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل Ch
#وصف_ڪريو Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل Maj
#وصف_ڪريو Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل OPENSSL_SMALL_FOOTPRINT

ساكن فراغ sha256_بلاڪ_معلومات_ترتيب(SHA256_CTX *ctx, ثابت فراغ *اندريون,
    size_t انگ)
{
    بنانشان MD32_REG_T a, b, c, d, e, f, g, h, s0, s1, T1, T2;
    SHA_LONG X[16], l;
    صحيح i;
    ثابت بنانشان حرف *معلومات = اندريون;

    طالما (انگ--) {

        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];

        لكل (i = 0; i < 16; i++) {
            (فراغ)HOST_c2l(معلومات, l);
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

        لكل (; i < 64; i++) {
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

#وإلا

#وصف_ڪريو ڦيرو_00_15(i, a, b, c, d, e, f, g, h)       \
    افعل {                                             \
        T1 += h + Sigma1(e) + Ch(e, f, g) + K256[i]; \
        h = Sigma0(a) + Maj(a, b, c);                \
        d += T1;                                     \
        h += T1;                                     \
    } طالما (0)

#وصف_ڪريو ڦيرو_16_63(i, a, b, c, d, e, f, g, h, X)          \
    افعل {                                                   \
        s0 = X[(i + 1) & 0x0f];                            \
        s0 = sigma0(s0);                                   \
        s1 = X[(i + 14) & 0x0f];                           \
        s1 = sigma1(s1);                                   \
        T1 = X[(i) & 0x0f] += s0 + s1 + X[(i + 9) & 0x0f]; \
        ڦيرو_00_15(i, a, b, c, d, e, f, g, h);            \
    } طالما (0)

#جيڪڏهن_وصف_ٿيل INCLUDE_C_SHA256
فراغ sha256_بلاڪ_معلومات_ترتيب_c(SHA256_CTX *ctx, ثابت فراغ *اندريون, size_t انگ)
#وإلا
ساكن فراغ sha256_بلاڪ_معلومات_ترتيب(SHA256_CTX *ctx, ثابت فراغ *اندريون,
    size_t انگ)
#جيڪڏهن_پورو
{
    بنانشان MD32_REG_T a, b, c, d, e, f, g, h, s0, s1, T1;
    SHA_LONG X[16];
    صحيح i;
    ثابت بنانشان حرف *معلومات = اندريون;
    DECLARE_IS_ENDIAN;

    طالما (انگ--) {

        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];

        إذا (!IS_LITTLE_ENDIAN && حجم(SHA_LONG) == 4
            && ((size_t)اندريون % 4) == 0) {
            ثابت SHA_LONG *W = (ثابت SHA_LONG *)معلومات;

            T1 = X[0] = W[0];
            ڦيرو_00_15(0, a, b, c, d, e, f, g, h);
            T1 = X[1] = W[1];
            ڦيرو_00_15(1, h, a, b, c, d, e, f, g);
            T1 = X[2] = W[2];
            ڦيرو_00_15(2, g, h, a, b, c, d, e, f);
            T1 = X[3] = W[3];
            ڦيرو_00_15(3, f, g, h, a, b, c, d, e);
            T1 = X[4] = W[4];
            ڦيرو_00_15(4, e, f, g, h, a, b, c, d);
            T1 = X[5] = W[5];
            ڦيرو_00_15(5, d, e, f, g, h, a, b, c);
            T1 = X[6] = W[6];
            ڦيرو_00_15(6, c, d, e, f, g, h, a, b);
            T1 = X[7] = W[7];
            ڦيرو_00_15(7, b, c, d, e, f, g, h, a);
            T1 = X[8] = W[8];
            ڦيرو_00_15(8, a, b, c, d, e, f, g, h);
            T1 = X[9] = W[9];
            ڦيرو_00_15(9, h, a, b, c, d, e, f, g);
            T1 = X[10] = W[10];
            ڦيرو_00_15(10, g, h, a, b, c, d, e, f);
            T1 = X[11] = W[11];
            ڦيرو_00_15(11, f, g, h, a, b, c, d, e);
            T1 = X[12] = W[12];
            ڦيرو_00_15(12, e, f, g, h, a, b, c, d);
            T1 = X[13] = W[13];
            ڦيرو_00_15(13, d, e, f, g, h, a, b, c);
            T1 = X[14] = W[14];
            ڦيرو_00_15(14, c, d, e, f, g, h, a, b);
            T1 = X[15] = W[15];
            ڦيرو_00_15(15, b, c, d, e, f, g, h, a);

            معلومات += SHA256_CBLOCK;
        } وإلا {
            SHA_LONG l;

            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[0] = l;
            ڦيرو_00_15(0, a, b, c, d, e, f, g, h);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[1] = l;
            ڦيرو_00_15(1, h, a, b, c, d, e, f, g);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[2] = l;
            ڦيرو_00_15(2, g, h, a, b, c, d, e, f);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[3] = l;
            ڦيرو_00_15(3, f, g, h, a, b, c, d, e);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[4] = l;
            ڦيرو_00_15(4, e, f, g, h, a, b, c, d);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[5] = l;
            ڦيرو_00_15(5, d, e, f, g, h, a, b, c);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[6] = l;
            ڦيرو_00_15(6, c, d, e, f, g, h, a, b);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[7] = l;
            ڦيرو_00_15(7, b, c, d, e, f, g, h, a);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[8] = l;
            ڦيرو_00_15(8, a, b, c, d, e, f, g, h);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[9] = l;
            ڦيرو_00_15(9, h, a, b, c, d, e, f, g);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[10] = l;
            ڦيرو_00_15(10, g, h, a, b, c, d, e, f);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[11] = l;
            ڦيرو_00_15(11, f, g, h, a, b, c, d, e);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[12] = l;
            ڦيرو_00_15(12, e, f, g, h, a, b, c, d);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[13] = l;
            ڦيرو_00_15(13, d, e, f, g, h, a, b, c);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[14] = l;
            ڦيرو_00_15(14, c, d, e, f, g, h, a, b);
            (فراغ)HOST_c2l(معلومات, l);
            T1 = X[15] = l;
            ڦيرو_00_15(15, b, c, d, e, f, g, h, a);
        }

        لكل (i = 16; i < 64; i += 8) {
            ڦيرو_16_63(i + 0, a, b, c, d, e, f, g, h, X);
            ڦيرو_16_63(i + 1, h, a, b, c, d, e, f, g, X);
            ڦيرو_16_63(i + 2, g, h, a, b, c, d, e, f, X);
            ڦيرو_16_63(i + 3, f, g, h, a, b, c, d, e, X);
            ڦيرو_16_63(i + 4, e, f, g, h, a, b, c, d, X);
            ڦيرو_16_63(i + 5, d, e, f, g, h, a, b, c, X);
            ڦيرو_16_63(i + 6, c, d, e, f, g, h, a, b, X);
            ڦيرو_16_63(i + 7, b, c, d, e, f, g, h, a, X);
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

#جيڪڏهن_پورو
#جيڪڏهن_پورو /* SHA256_ASM */
