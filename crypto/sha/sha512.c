/*
 * Copyright 2004-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * SHA512 low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#ضمن "internal/deprecated.h"

#ضمن <stdio.h>
#ضمن <openssl/opensslconf.h>
#ضمن <openssl/byteorder.h>
/*-
 * IMPLEMENTATION NOTES.
 *
 * As you might have noticed, 32-bit hash algorithms:
 *
 * - permit SHA_LONG to be wider than 32-bit
 * - optimized versions implement two transform functions: one operating
 *   on [aligned] data in host byte order, and one operating on data in input
 *   stream byte order;
 * - share common byte-order neutral collector and padding function
 *   implementations, crypto/md32_common.inc;
 *
 * Neither of the above applies to this SHA-512 implementation. Reasons
 * [in reverse order] are:
 *
 * - it's the only 64-bit hash algorithm for the moment of this writing,
 *   there is no need for common collector/padding implementation [yet];
 * - by supporting only one transform function [which operates on
 *   *aligned* data in input stream byte order, big-endian in this case]
 *   we minimize burden of maintenance in two ways: a) collector/padding
 *   function is simpler; b) only one transform function to stare at;
 * - SHA_LONG64 is required to be exactly 64-bit in order to be able to
 *   apply a number of optimizations to mitigate potential performance
 *   penalties caused by previous design decision;
 *
 * Caveat lector.
 *
 * Implementation relies on the fact that "long long" is 64-bit on
 * both 32- and 64-bit platforms. If some compiler vendor comes up
 * with 128-bit long long, adjustment to sha.h would be required.
 * As this implementation relies on 64-bit integer type, it's totally
 * inappropriate for platforms which don't support it, most notably
 * 16-bit platforms.
 */
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن <openssl/crypto.h>
#ضمن <openssl/sha.h>
#ضمن <openssl/opensslv.h>

#ضمن "internal/cryptlib.h"
#ضمن "crypto/sha.h"

#إذا defined(__i386) || defined(__i386__) || defined(_M_IX86) || defined(__x86_64) || defined(_M_AMD64) || defined(_M_X64) || defined(__s390__) || defined(__s390x__) || defined(__aarch64__) || defined(__e2k__) || defined(SHA512_ASM)
#تعریف_کړه SHA512_بلاک_CAN_MANAGE_UNALIGNED_معلومات
#د_که_پای

#إذا (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#تعریف_کړه U64(C) C##UI64
#وإلاإذا defined(__arch64__)
#تعریف_کړه U64(C) C##UL
#وإلا
#تعریف_کړه U64(C) C##ULL
#د_که_پای

صحيح SHA512_Update_thunk(فراغ *cp, ثابت بینښه حرف *معلومات, size_t len);

صحيح sha512_224_init(SHA512_CTX *c)
{
    c->h[0] = U64(0x8c3d37c819544da2);
    c->h[1] = U64(0x73e1996689dcd4d6);
    c->h[2] = U64(0x1dfab7ae32ff9c82);
    c->h[3] = U64(0x679dd514582f9fcf);
    c->h[4] = U64(0x0f6d2b697bd44da8);
    c->h[5] = U64(0x77e36f7304c48942);
    c->h[6] = U64(0x3f9d85a86a1d36c8);
    c->h[7] = U64(0x1112e6ad91d692a1);

    c->Nl = 0;
    c->Nh = 0;
    c->عدد = 0;
    c->md_len = SHA224_DIGEST_اوږدتیا;
    أرجع 1;
}

صحيح sha512_256_init(SHA512_CTX *c)
{
    c->h[0] = U64(0x22312194fc2bf72c);
    c->h[1] = U64(0x9f555fa3c84c64c2);
    c->h[2] = U64(0x2393b86b6f53b151);
    c->h[3] = U64(0x963877195940eabd);
    c->h[4] = U64(0x96283ee2a88effe3);
    c->h[5] = U64(0xbe5e1e2553863992);
    c->h[6] = U64(0x2b0199fc2c85b8aa);
    c->h[7] = U64(0x0eb72ddc81c52ca2);

    c->Nl = 0;
    c->Nh = 0;
    c->عدد = 0;
    c->md_len = SHA256_DIGEST_اوږدتیا;
    أرجع 1;
}

صحيح SHA384_Init(SHA512_CTX *c)
{
    c->h[0] = U64(0xcbbb9d5dc1059ed8);
    c->h[1] = U64(0x629a292a367cd507);
    c->h[2] = U64(0x9159015a3070dd17);
    c->h[3] = U64(0x152fecd8f70e5939);
    c->h[4] = U64(0x67332667ffc00b31);
    c->h[5] = U64(0x8eb44a8768581511);
    c->h[6] = U64(0xdb0c2e0d64f98fa7);
    c->h[7] = U64(0x47b5481dbefa4fa4);

    c->Nl = 0;
    c->Nh = 0;
    c->عدد = 0;
    c->md_len = SHA384_DIGEST_اوږدتیا;
    أرجع 1;
}

صحيح SHA512_Init(SHA512_CTX *c)
{
    c->h[0] = U64(0x6a09e667f3bcc908);
    c->h[1] = U64(0xbb67ae8584caa73b);
    c->h[2] = U64(0x3c6ef372fe94f82b);
    c->h[3] = U64(0xa54ff53a5f1d36f1);
    c->h[4] = U64(0x510e527fade682d1);
    c->h[5] = U64(0x9b05688c2b3e6c1f);
    c->h[6] = U64(0x1f83d9abfb41bd6b);
    c->h[7] = U64(0x5be0cd19137e2179);

    c->Nl = 0;
    c->Nh = 0;
    c->عدد = 0;
    c->md_len = SHA512_DIGEST_اوږدتیا;
    أرجع 1;
}

#که_نه_تعریف_شوی SHA512_ASM
ساكن
#وإلا
#که_تعریف_شوی INCLUDE_C_SHA512
فراغ sha512_بلاک_معلومات_ترتیب_c(SHA512_CTX *ctx, ثابت فراغ *دننه, size_t عدد);
#د_که_پای
#د_که_پای
    فراغ sha512_بلاک_معلومات_ترتیب(SHA512_CTX *ctx, ثابت فراغ *دننه, size_t عدد);

#تعریف_کړه OUTPUT_پایله(md, len)      \
    لكل (n = 0; n < (len / 8); n++) \
    md = OPENSSL_store_u64_be(md, (uint64_t)c->h[n])

صحيح SHA512_Final(بینښه حرف *بهر, SHA512_CTX *c)
{
    بینښه حرف *p = (بینښه حرف *)c->u.p;
    size_t n = c->عدد;

    p[n] = 0x80; /* There always is a room for one */
    n++;
    إذا (n > (حجم(c->u) - 16)) {
        memset(p + n, 0, حجم(c->u) - n);
        n = 0;
        sha512_بلاک_معلومات_ترتیب(c, p, 1);
    }

    memset(p + n, 0, حجم(c->u) - 16 - n);
#که_تعریف_شوی B_ENDIAN
    c->u.d[SHA_LBLOCK - 2] = c->Nh;
    c->u.d[SHA_LBLOCK - 1] = c->Nl;
#وإلا
    uint8_t *cu = p + حجم(c->u) - 16;

    cu = OPENSSL_store_u64_be(cu, (uint64_t)c->Nh);
    cu = OPENSSL_store_u64_be(cu, (uint64_t)c->Nl);
#د_که_پای

    sha512_بلاک_معلومات_ترتیب(c, p, 1);

    إذا (بهر == عدم)
        أرجع 0;

    /* Let compiler decide if it's appropriate to unroll... */
    بدل (c->md_len) {
    حالة SHA256_192_DIGEST_اوږدتیا:
        OUTPUT_پایله(بهر, SHA256_192_DIGEST_اوږدتیا);
        اكسر;
    حالة SHA256_DIGEST_اوږدتیا:
        OUTPUT_پایله(بهر, SHA256_DIGEST_اوږدتیا);
        اكسر;
    حالة SHA384_DIGEST_اوږدتیا:
        OUTPUT_پایله(بهر, SHA384_DIGEST_اوږدتیا);
        اكسر;
    حالة SHA512_DIGEST_اوږدتیا:
        OUTPUT_پایله(بهر, SHA512_DIGEST_اوږدتیا);
        اكسر;
    حالة SHA224_DIGEST_اوږدتیا: {
        OUTPUT_پایله(بهر, SHA224_DIGEST_اوږدتیا);
        /*
         * For 224 bits, there are four bytes left over that have to be
         * processed separately.
         */
        {
            SHA_LONG64 t = c->h[SHA224_DIGEST_اوږدتیا / 8];

            *(بهر++) = (بینښه حرف)(t >> 56);
            *(بهر++) = (بینښه حرف)(t >> 48);
            *(بهر++) = (بینښه حرف)(t >> 40);
            *(بهر++) = (بینښه حرف)(t >> 32);
        }
        اكسر;
    }
    /* ... as well as make sure md_len is not abused. */
    افتراضي:
        أرجع 0;
    }

    أرجع 1;
}

صحيح SHA384_Final(بینښه حرف *md, SHA512_CTX *c)
{
    أرجع SHA512_Final(md, c);
}

صحيح SHA512_Update_thunk(فراغ *cp, ثابت بینښه حرف *معلومات, size_t len)
{
    SHA512_CTX *c = (SHA512_CTX *)cp;
    SHA_LONG64 l;
    بینښه حرف *p = c->u.p;

    إذا (len == 0)
        أرجع 1;

    l = (c->Nl + (((SHA_LONG64)len) << 3)) & U64(0xffffffffffffffff);
    إذا (l < c->Nl)
        c->Nh++;
    إذا (حجم(len) >= 8)
        c->Nh += (((SHA_LONG64)len) >> 61);
    c->Nl = l;

    إذا (c->عدد != 0) {
        size_t n = حجم(c->u) - c->عدد;

        إذا (len < n) {
            حافظه_نقل(p + c->عدد, معلومات, len), c->عدد += (بینښه صحيح)len;
            أرجع 1;
        } وإلا {
            حافظه_نقل(p + c->عدد, معلومات, n), c->عدد = 0;
            len -= n, معلومات += n;
            sha512_بلاک_معلومات_ترتیب(c, p, 1);
        }
    }

    إذا (len >= حجم(c->u)) {
#که_نه_تعریف_شوی SHA512_بلاک_CAN_MANAGE_UNALIGNED_معلومات
        إذا ((size_t)معلومات % حجم(c->u.d[0]) != 0)
            طالما (len >= حجم(c->u))
                حافظه_نقل(p, معلومات, حجم(c->u)),
                    sha512_بلاک_معلومات_ترتیب(c, p, 1),
                    len -= حجم(c->u), معلومات += حجم(c->u);
        وإلا
#د_که_پای
            sha512_بلاک_معلومات_ترتیب(c, معلومات, len / حجم(c->u)),
                معلومات += len, len %= حجم(c->u), معلومات -= len;
    }

    إذا (len != 0)
        حافظه_نقل(p, معلومات, len), c->عدد = (صحيح)len;

    أرجع 1;
}

صحيح SHA512_Update(SHA512_CTX *c, ثابت فراغ *معلومات_2, size_t len)
{
    أرجع SHA512_Update_thunk((فراغ *)c, (ثابت بینښه حرف *)معلومات_2, len);
}

صحيح SHA384_Update(SHA512_CTX *c, ثابت فراغ *معلومات, size_t len)
{
    أرجع SHA512_Update_thunk((فراغ *)c, (ثابت بینښه حرف *)معلومات, len);
}

فراغ SHA512_Transform(SHA512_CTX *c, ثابت بینښه حرف *معلومات)
{
#که_نه_تعریف_شوی SHA512_بلاک_CAN_MANAGE_UNALIGNED_معلومات
    إذا ((size_t)معلومات % حجم(c->u.d[0]) != 0)
        حافظه_نقل(c->u.p, معلومات, حجم(c->u.p)), معلومات = c->u.p;
#د_که_پای
    sha512_بلاک_معلومات_ترتیب(c, معلومات, 1);
}

#إذا !defined(SHA512_ASM) || defined(INCLUDE_C_SHA512)
ساكن ثابت SHA_LONG64 K512[80] = {
    U64(0x428a2f98d728ae22), U64(0x7137449123ef65cd),
    U64(0xb5c0fbcfec4d3b2f), U64(0xe9b5dba58189dbbc),
    U64(0x3956c25bf348b538), U64(0x59f111f1b605d019),
    U64(0x923f82a4af194f9b), U64(0xab1c5ed5da6d8118),
    U64(0xd807aa98a3030242), U64(0x12835b0145706fbe),
    U64(0x243185be4ee4b28c), U64(0x550c7dc3d5ffb4e2),
    U64(0x72be5d74f27b896f), U64(0x80deb1fe3b1696b1),
    U64(0x9bdc06a725c71235), U64(0xc19bf174cf692694),
    U64(0xe49b69c19ef14ad2), U64(0xefbe4786384f25e3),
    U64(0x0fc19dc68b8cd5b5), U64(0x240ca1cc77ac9c65),
    U64(0x2de92c6f592b0275), U64(0x4a7484aa6ea6e483),
    U64(0x5cb0a9dcbd41fbd4), U64(0x76f988da831153b5),
    U64(0x983e5152ee66dfab), U64(0xa831c66d2db43210),
    U64(0xb00327c898fb213f), U64(0xbf597fc7beef0ee4),
    U64(0xc6e00bf33da88fc2), U64(0xd5a79147930aa725),
    U64(0x06ca6351e003826f), U64(0x142929670a0e6e70),
    U64(0x27b70a8546d22ffc), U64(0x2e1b21385c26c926),
    U64(0x4d2c6dfc5ac42aed), U64(0x53380d139d95b3df),
    U64(0x650a73548baf63de), U64(0x766a0abb3c77b2a8),
    U64(0x81c2c92e47edaee6), U64(0x92722c851482353b),
    U64(0xa2bfe8a14cf10364), U64(0xa81a664bbc423001),
    U64(0xc24b8b70d0f89791), U64(0xc76c51a30654be30),
    U64(0xd192e819d6ef5218), U64(0xd69906245565a910),
    U64(0xf40e35855771202a), U64(0x106aa07032bbd1b8),
    U64(0x19a4c116b8d2d0c8), U64(0x1e376c085141ab53),
    U64(0x2748774cdf8eeb99), U64(0x34b0bcb5e19b48a8),
    U64(0x391c0cb3c5c95a63), U64(0x4ed8aa4ae3418acb),
    U64(0x5b9cca4f7763e373), U64(0x682e6ff3d6b2b8a3),
    U64(0x748f82ee5defb2fc), U64(0x78a5636f43172f60),
    U64(0x84c87814a1f0ab72), U64(0x8cc702081a6439ec),
    U64(0x90befffa23631e28), U64(0xa4506cebde82bde9),
    U64(0xbef9a3f7b2c67915), U64(0xc67178f2e372532b),
    U64(0xca273eceea26619c), U64(0xd186b8c721c0c207),
    U64(0xeada7dd6cde0eb1e), U64(0xf57d4f7fee6ed178),
    U64(0x06f067aa72176fba), U64(0x0a637dc5a2c898a6),
    U64(0x113f9804bef90dae), U64(0x1b710b35131c471b),
    U64(0x28db77f523047d84), U64(0x32caab7b40c72493),
    U64(0x3c9ebe0a15c9bebc), U64(0x431d67c49c100d4c),
    U64(0x4cc5d4becb3e42b6), U64(0x597f299cfc657e2a),
    U64(0x5fcb6fab3ad6faec), U64(0x6c44198c4a475817)
};

#که_نه_تعریف_شوی PEDANTIC
#إذا defined(__GNUC__) && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
#إذا defined(__x86_64) || defined(__x86_64__)
#تعریف_کړه ROTR(a, n) ({ SHA_LONG64 ret;             \
                                asm ("rorq %1,%0"       \
                                : "=r"(ret)             \
                                : "J"(n),"0"(a)         \
                                : "cc"); ret; })
#إذا !defined(B_ENDIAN)
#تعریف_کړه PULL64(x) ({ SHA_LONG64 ret=*((ثابت SHA_LONG64 *)(&(x)));  \
                                asm ("bswapq    %0"             \
                                : "=r"(ret)                     \
                                : "0"(ret)); ret; })
#د_که_پای
#وإلاإذا (defined(__i386) || defined(__i386__)) && !defined(B_ENDIAN)
#إذا defined(I386_ONLY)
#تعریف_کړه PULL64(x) ({ ثابت بینښه صحيح *p=(ثابت بینښه صحيح *)(&(x));\
                          بینښه صحيح hi=p[0],lo=p[1];          \
                                asm("xchgb %%ah,%%al;xchgb %%dh,%%dl;"\
                                    "roll $16,%%eax; roll $16,%%edx; "\
                                    "xchgb %%ah,%%al;xchgb %%dh,%%dl;"\
                                : "=a"(lo),"=d"(hi)             \
                                : "0"(lo),"1"(hi) : "cc");      \
                                ((SHA_LONG64)hi)<<32|lo; })
#وإلا
#تعریف_کړه PULL64(x) ({ ثابت بینښه صحيح *p=(ثابت بینښه صحيح *)(&(x));\
                          بینښه صحيح hi=p[0],lo=p[1];         \
                                asm ("bswapl %0; bswapl %1;"    \
                                : "=r"(lo),"=r"(hi)             \
                                : "0"(lo),"1"(hi));             \
                                ((SHA_LONG64)hi)<<32|lo; })
#د_که_پای
#وإلاإذا (defined(_ARCH_PPC) && defined(__64BIT__)) || defined(_ARCH_PPC64)
#تعریف_کړه ROTR(a, n) ({ SHA_LONG64 ret;             \
                                asm ("rotrdi %0,%1,%2"  \
                                : "=r"(ret)             \
                                : "r"(a),"K"(n)); ret; })
#وإلاإذا defined(__aarch64__)
#تعریف_کړه ROTR(a, n) ({ SHA_LONG64 ret;             \
                                asm ("ror %0,%1,%2"     \
                                : "=r"(ret)             \
                                : "r"(a),"I"(n)); ret; })
#إذا defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#تعریف_کړه PULL64(x) ({ SHA_LONG64 ret;                     \
                                asm ("rev       %0,%1"          \
                                : "=r"(ret)                     \
                                : "r"(*((ثابت SHA_LONG64 *)(&(x))))); ret; })
#د_که_پای
#وإلاإذا (defined(__riscv_zbkb) || defined(__riscv_zbb)) && __riscv_xlen == 32
#تعریف_کړه PULL64(x) ({ SHA_LONG64 ret;                                        \
                        بینښه صحيح *r = (بینښه صحيح *)(&(ret));             \
                        ثابت بینښه صحيح *p = (ثابت بینښه صحيح *)(&(x));   \
                        asm ("rev8 %0, %1"                                      \
                        : "=r"(r[0])                                            \
                        : "r" (p[1]));                                          \
                        asm ("rev8 %0, %1"                                      \
                        : "=r"(r[1])                                            \
                        : "r" (p[0])); ret; })
#وإلاإذا (defined(__riscv_zbkb) || defined(__riscv_zbb)) && __riscv_xlen == 64
#تعریف_کړه PULL64(x) ({ SHA_LONG64 ret;    \
                        asm ("rev8 %0, %1"  \
                        : "=r"(ret)         \
                        : "r"(x)); ret; })
#وإلاإذا defined(__e2k__)
#ضمن <x86gprintrin.h>
#تعریف_کړه PULL64(x) __builtin_bswap64(x)
#تعریف_کړه ROTR(x, s) ((s) > 48 ? __rolq((x), 64 - (s)) \
                             : __rorq((x), (s)))
#د_که_پای
#إذا defined(__riscv_zknh) && __riscv_xlen == 32
#تعریف_کړه Sigma0(x) ({ SHA_LONG64 ret; بینښه صحيح *r = (بینښه صحيح *)(&(ret));    \
                        ثابت بینښه صحيح *p = (ثابت بینښه صحيح *)(&(x));           \
                        asm ("sha512sum0r %0, %1, %2"                                   \
                        : "=r"(r[0])                                                    \
                        : "r" (p[0]), "r" (p[1]));                                      \
                        asm ("sha512sum0r %0, %2, %1"                                   \
                        : "=r"(r[1])                                                    \
                        : "r" (p[0]), "r" (p[1])); ret; })
#تعریف_کړه Sigma1(x) ({ SHA_LONG64 ret; بینښه صحيح *r = (بینښه صحيح *)(&(ret));    \
                        ثابت بینښه صحيح *p = (ثابت بینښه صحيح *)(&(x));           \
                        asm ("sha512sum1r %0, %1, %2"                                   \
                        : "=r"(r[0])                                                    \
                        : "r" (p[0]), "r" (p[1]));                                      \
                        asm ("sha512sum1r %0, %2, %1"                                   \
                        : "=r"(r[1])                                                    \
                        : "r" (p[0]), "r" (p[1])); ret; })
#تعریف_کړه sigma0(x) ({ SHA_LONG64 ret; بینښه صحيح *r = (بینښه صحيح *)(&(ret));    \
                        ثابت بینښه صحيح *p = (ثابت بینښه صحيح *)(&(x));           \
                        asm ("sha512sig0l %0, %1, %2"                                   \
                        : "=r"(r[0])                                                    \
                        : "r" (p[0]), "r" (p[1]));                                      \
                        asm ("sha512sig0h %0, %2, %1"                                   \
                        : "=r"(r[1])                                                    \
                        : "r" (p[0]), "r" (p[1])); ret; })
#تعریف_کړه sigma1(x) ({ SHA_LONG64 ret; بینښه صحيح *r = (بینښه صحيح *)(&(ret));    \
                        ثابت بینښه صحيح *p = (ثابت بینښه صحيح *)(&(x));           \
                        asm ("sha512sig1l %0, %1, %2"                                   \
                        : "=r"(r[0])                                                    \
                        : "r" (p[0]), "r" (p[1]));                                      \
                        asm ("sha512sig1h %0, %2, %1"                                   \
                        : "=r"(r[1])                                                    \
                        : "r" (p[0]), "r" (p[1])); ret; })
#وإلاإذا defined(__riscv_zknh) && __riscv_xlen == 64
#تعریف_کړه Sigma0(x) ({ SHA_LONG64 ret;            \
                        asm ("sha512sum0 %0, %1"    \
                        : "=r"(ret)                 \
                        : "r"(x)); ret; })
#تعریف_کړه Sigma1(x) ({ SHA_LONG64 ret;            \
                        asm ("sha512sum1 %0, %1"    \
                        : "=r"(ret)                 \
                        : "r"(x)); ret; })
#تعریف_کړه sigma0(x) ({ SHA_LONG64 ret;            \
                        asm ("sha512sig0 %0, %1"    \
                        : "=r"(ret)                 \
                        : "r"(x)); ret; })
#تعریف_کړه sigma1(x) ({ SHA_LONG64 ret;            \
                        asm ("sha512sig1 %0, %1"    \
                        : "=r"(ret)                 \
                        : "r"(x)); ret; })
#د_که_پای
#إذا (defined(__riscv_zbt) || defined(__riscv_zpn)) && __riscv_xlen == 32
#تعریف_کړه Ch(x, y, z) ({  SHA_LONG64 ret; بینښه صحيح *r = (بینښه صحيح *)(&(ret));   \
                        ثابت بینښه صحيح *xp = (ثابت بینښه صحيح *)(&(x));          \
                        ثابت بینښه صحيح *yp = (ثابت بینښه صحيح *)(&(y));          \
                        ثابت بینښه صحيح *zp = (ثابت بینښه صحيح *)(&(z));          \
                        asm (".insn r4 0x33, 1, 0x3, %0, %2, %1, %3\n\t"                \
                        : "=r"(r[0])                                                    \
                        : "r"(xp[0]), "r"(yp[0]), "r"(zp[0]));                          \
                        asm (".insn r4 0x33, 1, 0x3, %0, %2, %1, %3\n\t"                \
                        : "=r"(r[1])                                                    \
                        : "r"(xp[1]), "r"(yp[1]), "r"(zp[1])); ret; })
#تعریف_کړه Maj(x, y, z) ({ SHA_LONG64 ret; بینښه صحيح *r = (بینښه صحيح *)(&(ret));   \
                        ثابت بینښه صحيح *xp = (ثابت بینښه صحيح *)(&(x));          \
                        ثابت بینښه صحيح *yp = (ثابت بینښه صحيح *)(&(y));          \
                        ثابت بینښه صحيح *zp = (ثابت بینښه صحيح *)(&(z));          \
                        asm (".insn r4 0x33, 1, 0x3, %0, %2, %1, %3\n\t"                \
                        : "=r"(r[0])                                                    \
                        : "r"(xp[0]^zp[0]), "r"(yp[0]), "r"(zp[0]));                    \
                        asm (".insn r4 0x33, 1, 0x3, %0, %2, %1, %3\n\t"                \
                        : "=r"(r[1])                                                    \
                        : "r"(xp[1]^zp[1]), "r"(yp[1]), "r"(zp[1])); ret; })
#وإلاإذا (defined(__riscv_zbt) || defined(__riscv_zpn)) && __riscv_xlen == 64
#تعریف_کړه Ch(x, y, z) ({  SHA_LONG64 ret;                           \
                        asm (".insn r4 0x33, 1, 0x3, %0, %2, %1, %3"\
                        : "=r"(ret)                                 \
                        : "r"(x), "r"(y), "r"(z)); ret; })
#تعریف_کړه Maj(x, y, z) ({ SHA_LONG64 ret;                           \
                        asm (".insn r4 0x33, 1, 0x3, %0, %2, %1, %3"\
                        : "=r"(ret)                                 \
                        : "r"(x^z), "r"(y), "r"(x)); ret; })
#وإلاإذا defined(__e2k__) && __iset__ >= 5
#تعریف_کړه sigma0(x) (__builtin_e2k_plog(0x96, ROTR((x), 1), ROTR((x), 8), ((x) >> 7)))
#تعریف_کړه sigma1(x) (__builtin_e2k_plog(0x96, ROTR((x), 19), ROTR((x), 61), ((x) >> 6)))
#د_که_پای
#وإلاإذا defined(_MSC_VER)
#إذا defined(_WIN64) /* applies to both IA-64 and AMD64 */
#لارښوونه intrinsic(_rotr64)
#تعریف_کړه ROTR(a, n) _rotr64((a), n)
#د_که_پای
#إذا defined(_M_IX86) && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
#إذا defined(I386_ONLY)
ساكن SHA_LONG64 __fastcall __pull64be(ثابت فراغ *x)
{
    _asm mov edx, [ecx + 0] _asm mov eax, [ecx + 4] _asm xchg dh, dl _asm xchg ah, al _asm rol edx, 16 _asm rol eax, 16 _asm xchg dh, dl _asm xchg ah, al
}
#وإلا
ساكن SHA_LONG64 __fastcall __pull64be(ثابت فراغ *x) {
    _asm mov edx, [ecx + 0] _asm mov eax, [ecx + 4] _asm bswap edx _asm bswap eax
}
#د_که_پای
#تعریف_کړه PULL64(x) __pull64be(&(x))
#د_که_پای
#د_که_پای
#د_که_پای
#که_نه_تعریف_شوی PULL64
#تعریف_کړه B(x, j) (((SHA_LONG64)(*(((ثابت بینښه حرف *)(&x)) + j))) << ((7 - j) * 8))
#تعریف_کړه PULL64(x) (B(x, 0) | B(x, 1) | B(x, 2) | B(x, 3) | B(x, 4) | B(x, 5) | B(x, 6) | B(x, 7))
#د_که_پای
#که_نه_تعریف_شوی ROTR
#تعریف_کړه ROTR(x, s) (((x) >> s) | (x) << (64 - s))
#د_که_پای
#که_نه_تعریف_شوی Sigma0
#تعریف_کړه Sigma0(x) (ROTR((x), 28) ^ ROTR((x), 34) ^ ROTR((x), 39))
#د_که_پای
#که_نه_تعریف_شوی Sigma1
#تعریف_کړه Sigma1(x) (ROTR((x), 14) ^ ROTR((x), 18) ^ ROTR((x), 41))
#د_که_پای
#که_نه_تعریف_شوی sigma0
#تعریف_کړه sigma0(x) (ROTR((x), 1) ^ ROTR((x), 8) ^ ((x) >> 7))
#د_که_پای
#که_نه_تعریف_شوی sigma1
#تعریف_کړه sigma1(x) (ROTR((x), 19) ^ ROTR((x), 61) ^ ((x) >> 6))
#د_که_پای
#که_نه_تعریف_شوی Ch
#تعریف_کړه Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#د_که_پای
#که_نه_تعریف_شوی Maj
#تعریف_کړه Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#د_که_پای

#إذا defined(__i386) || defined(__i386__) || defined(_M_IX86)
/*
 * This code should give better results on 32-bit CPU with less than
 * ~24 registers, both size and performance wise...
 */

ساكن فراغ sha512_بلاک_معلومات_ترتیب(SHA512_CTX *ctx, ثابت فراغ *دننه,
    size_t عدد)
{
    ثابت SHA_LONG64 *W = دننه;
    SHA_LONG64 A, E, T;
    SHA_LONG64 X[9 + 80], *F;
    صحيح i;

    طالما (عدد--) {

        F = X + 80;
        A = ctx->h[0];
        F[1] = ctx->h[1];
        F[2] = ctx->h[2];
        F[3] = ctx->h[3];
        E = ctx->h[4];
        F[5] = ctx->h[5];
        F[6] = ctx->h[6];
        F[7] = ctx->h[7];

        لكل (i = 0; i < 16; i++, F--) {
#که_تعریف_شوی B_ENDIAN
            T = W[i];
#وإلا
            T = PULL64(W[i]);
#د_که_پای
            F[0] = A;
            F[4] = E;
            F[8] = T;
            T += F[7] + Sigma1(E) + Ch(E, F[5], F[6]) + K512[i];
            E = F[3] + T;
            A = T + Sigma0(A) + Maj(A, F[1], F[2]);
        }

        لكل (; i < 80; i++, F--) {
            T = sigma0(F[8 + 16 - 1]);
            T += sigma1(F[8 + 16 - 14]);
            T += F[8 + 16] + F[8 + 16 - 9];

            F[0] = A;
            F[4] = E;
            F[8] = T;
            T += F[7] + Sigma1(E) + Ch(E, F[5], F[6]) + K512[i];
            E = F[3] + T;
            A = T + Sigma0(A) + Maj(A, F[1], F[2]);
        }

        ctx->h[0] += A;
        ctx->h[1] += F[1];
        ctx->h[2] += F[2];
        ctx->h[3] += F[3];
        ctx->h[4] += E;
        ctx->h[5] += F[5];
        ctx->h[6] += F[6];
        ctx->h[7] += F[7];

        W += SHA_LBLOCK;
    }
}

#وإلاإذا defined(OPENSSL_SMALL_FOOTPRINT)

ساكن فراغ sha512_بلاک_معلومات_ترتیب(SHA512_CTX *ctx, ثابت فراغ *دننه,
    size_t عدد)
{
    ثابت SHA_LONG64 *W = دننه;
    SHA_LONG64 a, b, c, d, e, f, g, h, s0, s1, T1, T2;
    SHA_LONG64 X[16];
    صحيح i;

    طالما (عدد--) {

        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];

        لكل (i = 0; i < 16; i++) {
#که_تعریف_شوی B_ENDIAN
            T1 = X[i] = W[i];
#وإلا
            T1 = X[i] = PULL64(W[i]);
#د_که_پای
            T1 += h + Sigma1(e) + Ch(e, f, g) + K512[i];
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

        لكل (; i < 80; i++) {
            s0 = X[(i + 1) & 0x0f];
            s0 = sigma0(s0);
            s1 = X[(i + 14) & 0x0f];
            s1 = sigma1(s1);

            T1 = X[i & 0xf] += s0 + s1 + X[(i + 9) & 0xf];
            T1 += h + Sigma1(e) + Ch(e, f, g) + K512[i];
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

        W += SHA_LBLOCK;
    }
}

#وإلا
#تعریف_کړه پړاو_00_15(i, a, b, c, d, e, f, g, h)       \
    افعل {                                             \
        T1 += h + Sigma1(e) + Ch(e, f, g) + K512[i]; \
        h = Sigma0(a) + Maj(a, b, c);                \
        d += T1;                                     \
        h += T1;                                     \
    } طالما (0)

#تعریف_کړه پړاو_16_80(i, j, a, b, c, d, e, f, g, h, X)       \
    افعل {                                                   \
        s0 = X[(j + 1) & 0x0f];                            \
        s0 = sigma0(s0);                                   \
        s1 = X[(j + 14) & 0x0f];                           \
        s1 = sigma1(s1);                                   \
        T1 = X[(j) & 0x0f] += s0 + s1 + X[(j + 9) & 0x0f]; \
        پړاو_00_15(i + j, a, b, c, d, e, f, g, h);        \
    } طالما (0)

#که_تعریف_شوی INCLUDE_C_SHA512
فراغ sha512_بلاک_معلومات_ترتیب_c(SHA512_CTX *ctx, ثابت فراغ *دننه, size_t عدد)
#وإلا
ساكن فراغ sha512_بلاک_معلومات_ترتیب(SHA512_CTX *ctx, ثابت فراغ *دننه,
    size_t عدد)
#د_که_پای
{
    ثابت SHA_LONG64 *W = دننه;
    SHA_LONG64 a, b, c, d, e, f, g, h, s0, s1, T1;
    SHA_LONG64 X[16];
    صحيح i;

    طالما (عدد--) {

        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];

#که_تعریف_شوی B_ENDIAN
        T1 = X[0] = W[0];
        پړاو_00_15(0, a, b, c, d, e, f, g, h);
        T1 = X[1] = W[1];
        پړاو_00_15(1, h, a, b, c, d, e, f, g);
        T1 = X[2] = W[2];
        پړاو_00_15(2, g, h, a, b, c, d, e, f);
        T1 = X[3] = W[3];
        پړاو_00_15(3, f, g, h, a, b, c, d, e);
        T1 = X[4] = W[4];
        پړاو_00_15(4, e, f, g, h, a, b, c, d);
        T1 = X[5] = W[5];
        پړاو_00_15(5, d, e, f, g, h, a, b, c);
        T1 = X[6] = W[6];
        پړاو_00_15(6, c, d, e, f, g, h, a, b);
        T1 = X[7] = W[7];
        پړاو_00_15(7, b, c, d, e, f, g, h, a);
        T1 = X[8] = W[8];
        پړاو_00_15(8, a, b, c, d, e, f, g, h);
        T1 = X[9] = W[9];
        پړاو_00_15(9, h, a, b, c, d, e, f, g);
        T1 = X[10] = W[10];
        پړاو_00_15(10, g, h, a, b, c, d, e, f);
        T1 = X[11] = W[11];
        پړاو_00_15(11, f, g, h, a, b, c, d, e);
        T1 = X[12] = W[12];
        پړاو_00_15(12, e, f, g, h, a, b, c, d);
        T1 = X[13] = W[13];
        پړاو_00_15(13, d, e, f, g, h, a, b, c);
        T1 = X[14] = W[14];
        پړاو_00_15(14, c, d, e, f, g, h, a, b);
        T1 = X[15] = W[15];
        پړاو_00_15(15, b, c, d, e, f, g, h, a);
#وإلا
        T1 = X[0] = PULL64(W[0]);
        پړاو_00_15(0, a, b, c, d, e, f, g, h);
        T1 = X[1] = PULL64(W[1]);
        پړاو_00_15(1, h, a, b, c, d, e, f, g);
        T1 = X[2] = PULL64(W[2]);
        پړاو_00_15(2, g, h, a, b, c, d, e, f);
        T1 = X[3] = PULL64(W[3]);
        پړاو_00_15(3, f, g, h, a, b, c, d, e);
        T1 = X[4] = PULL64(W[4]);
        پړاو_00_15(4, e, f, g, h, a, b, c, d);
        T1 = X[5] = PULL64(W[5]);
        پړاو_00_15(5, d, e, f, g, h, a, b, c);
        T1 = X[6] = PULL64(W[6]);
        پړاو_00_15(6, c, d, e, f, g, h, a, b);
        T1 = X[7] = PULL64(W[7]);
        پړاو_00_15(7, b, c, d, e, f, g, h, a);
        T1 = X[8] = PULL64(W[8]);
        پړاو_00_15(8, a, b, c, d, e, f, g, h);
        T1 = X[9] = PULL64(W[9]);
        پړاو_00_15(9, h, a, b, c, d, e, f, g);
        T1 = X[10] = PULL64(W[10]);
        پړاو_00_15(10, g, h, a, b, c, d, e, f);
        T1 = X[11] = PULL64(W[11]);
        پړاو_00_15(11, f, g, h, a, b, c, d, e);
        T1 = X[12] = PULL64(W[12]);
        پړاو_00_15(12, e, f, g, h, a, b, c, d);
        T1 = X[13] = PULL64(W[13]);
        پړاو_00_15(13, d, e, f, g, h, a, b, c);
        T1 = X[14] = PULL64(W[14]);
        پړاو_00_15(14, c, d, e, f, g, h, a, b);
        T1 = X[15] = PULL64(W[15]);
        پړاو_00_15(15, b, c, d, e, f, g, h, a);
#د_که_پای

        لكل (i = 16; i < 80; i += 16) {
            پړاو_16_80(i, 0, a, b, c, d, e, f, g, h, X);
            پړاو_16_80(i, 1, h, a, b, c, d, e, f, g, X);
            پړاو_16_80(i, 2, g, h, a, b, c, d, e, f, X);
            پړاو_16_80(i, 3, f, g, h, a, b, c, d, e, X);
            پړاو_16_80(i, 4, e, f, g, h, a, b, c, d, X);
            پړاو_16_80(i, 5, d, e, f, g, h, a, b, c, X);
            پړاو_16_80(i, 6, c, d, e, f, g, h, a, b, X);
            پړاو_16_80(i, 7, b, c, d, e, f, g, h, a, X);
            پړاو_16_80(i, 8, a, b, c, d, e, f, g, h, X);
            پړاو_16_80(i, 9, h, a, b, c, d, e, f, g, X);
            پړاو_16_80(i, 10, g, h, a, b, c, d, e, f, X);
            پړاو_16_80(i, 11, f, g, h, a, b, c, d, e, X);
            پړاو_16_80(i, 12, e, f, g, h, a, b, c, d, X);
            پړاو_16_80(i, 13, d, e, f, g, h, a, b, c, X);
            پړاو_16_80(i, 14, c, d, e, f, g, h, a, b, X);
            پړاو_16_80(i, 15, b, c, d, e, f, g, h, a, X);
        }

        ctx->h[0] += a;
        ctx->h[1] += b;
        ctx->h[2] += c;
        ctx->h[3] += d;
        ctx->h[4] += e;
        ctx->h[5] += f;
        ctx->h[6] += g;
        ctx->h[7] += h;

        W += SHA_LBLOCK;
    }
}

#د_که_پای

#د_که_پای /* SHA512_ASM */
