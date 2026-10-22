/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ಆದರೆ !defined(OSSL_LIBCRYPTO_SHA_SHA_LOCAL_H)
#ವ್ಯಾಖ್ಯಾನಿಸು OSSL_LIBCRYPTO_SHA_SHA_LOCAL_H

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <openssl/opensslconf.h>
#ಅನ್ತರ್ಭಾವ <openssl/sha.h>
#ಅನ್ತರ್ಭಾವ "internal/endian.h"

#ವ್ಯಾಖ್ಯಾನಿಸು ದತ್ತಾಂಶ_ಕ್ರಮ_IS_BIG_ENDIAN

#ವ್ಯಾಖ್ಯಾನಿಸು HASH_LONG SHA_LONG
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_CTX SHA_CTX
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_CBLOCK SHA_CBLOCK
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_MAKE_STRING(c, s)   \
    ಮಾಡು {                         \
        ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ll;        \
        ll = (c)->h0;            \
        (ಶೂನ್ಯ)HOST_l2c(ll, (s)); \
        ll = (c)->h1;            \
        (ಶೂನ್ಯ)HOST_l2c(ll, (s)); \
        ll = (c)->h2;            \
        (ಶೂನ್ಯ)HOST_l2c(ll, (s)); \
        ll = (c)->h3;            \
        (ಶೂನ್ಯ)HOST_l2c(ll, (s)); \
        ll = (c)->h4;            \
        (ಶೂನ್ಯ)HOST_l2c(ll, (s)); \
    } ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು HASH_UPDATE_THUNK
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_UPDATE SHA1_Update_thunk
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_TRANSFORM SHA1_Transform
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_FINAL SHA1_Final
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_INIT SHA1_Init
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ sha1_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ
#ವ್ಯಾಖ್ಯಾನಿಸು Xupdate(a, ix, ia, ib, ic, id) ((a) = (ia ^ ib ^ ic ^ id), \
    ix = (a) = ROTATE((a), 1))

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SHA1_ASM
ಸ್ಥಿರ ಶೂನ್ಯ sha1_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(SHA_CTX *c, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *p, size_t ಅಂಕೆ);
#ಇಲ್ಲದಿದ್ದರೆ
ಶೂನ್ಯ sha1_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(SHA_CTX *c, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *p, size_t ಅಂಕೆ);
#ಆದರೆ_ಅಂತ್ಯ

/* clang-format off */
#ಅನ್ತರ್ಭಾವ "crypto/md32_common.inc"
/* clang-format on */
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು HASH_UPDATE_THUNK

ಪೂರ್ಣಾಂಕ SHA1_Update(SHA_CTX *c, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ದತ್ತಾಂಶ, size_t len)
{
    ಹಿಂತಿರುಗಿ SHA1_Update_thunk((ಶೂನ್ಯ *)c, (ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *)ದತ್ತಾಂಶ, len);
}

#ವ್ಯಾಖ್ಯಾನಿಸು INIT_ದತ್ತಾಂಶ_h0 0x67452301UL
#ವ್ಯಾಖ್ಯಾನಿಸು INIT_ದತ್ತಾಂಶ_h1 0xefcdab89UL
#ವ್ಯಾಖ್ಯಾನಿಸು INIT_ದತ್ತಾಂಶ_h2 0x98badcfeUL
#ವ್ಯಾಖ್ಯಾನಿಸು INIT_ದತ್ತಾಂಶ_h3 0x10325476UL
#ವ್ಯಾಖ್ಯಾನಿಸು INIT_ದತ್ತಾಂಶ_h4 0xc3d2e1f0UL

ಪೂರ್ಣಾಂಕ HASH_INIT(SHA_CTX *c)
{
    memset(c, 0, ಗಾತ್ರ(*c));
    c->h0 = INIT_ದತ್ತಾಂಶ_h0;
    c->h1 = INIT_ದತ್ತಾಂಶ_h1;
    c->h2 = INIT_ದತ್ತಾಂಶ_h2;
    c->h3 = INIT_ದತ್ತಾಂಶ_h3;
    c->h4 = INIT_ದತ್ತಾಂಶ_h4;
    ಹಿಂತಿರುಗಿ 1;
}

#ವ್ಯಾಖ್ಯಾನಿಸು K_00_19 0x5a827999UL
#ವ್ಯಾಖ್ಯಾನಿಸು K_20_39 0x6ed9eba1UL
#ವ್ಯಾಖ್ಯಾನಿಸು K_40_59 0x8f1bbcdcUL
#ವ್ಯಾಖ್ಯಾನಿಸು K_60_79 0xca62c1d6UL

/*
 * As pointed out by Wei Dai, F() below can be simplified to the code in
 * F_00_19.  Wei attributes these optimizations to Peter Gutmann's SHS code,
 * and he attributes it to Rich Schroeppel.
 *      #define F(x,y,z) (((x) & (y)) | ((~(x)) & (z)))
 * I've just become aware of another tweak to be made, again from Wei Dai,
 * in F_40_59, (x&a)|(y&a) -> (x|y)&a
 */
#ವ್ಯಾಖ್ಯಾನಿಸು F_00_19(b, c, d) ((((c) ^ (d)) & (b)) ^ (d))
#ವ್ಯಾಖ್ಯಾನಿಸು F_20_39(b, c, d) ((b) ^ (c) ^ (d))
#ವ್ಯಾಖ್ಯಾನಿಸು F_40_59(b, c, d) (((b) & (c)) | (((b) | (c)) & (d)))
#ವ್ಯಾಖ್ಯಾನಿಸು F_60_79(b, c, d) F_20_39(b, c, d)

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ OPENSSL_SMALL_FOOTPRINT

#ವ್ಯಾಖ್ಯಾನಿಸು BODY_00_15(i, a, b, c, d, e, f, xi)                             \
    (f) = xi + (e) + K_00_19 + ROTATE((a), 5) + F_00_19((b), (c), (d)); \
    (b) = ROTATE((b), 30);

#ವ್ಯಾಖ್ಯಾನಿಸು BODY_16_19(i, a, b, c, d, e, f, xi, xa, xb, xc, xd)         \
    Xupdate(f, xi, xa, xb, xc, xd);                                 \
    (f) += (e) + K_00_19 + ROTATE((a), 5) + F_00_19((b), (c), (d)); \
    (b) = ROTATE((b), 30);

#ವ್ಯಾಖ್ಯಾನಿಸು BODY_20_31(i, a, b, c, d, e, f, xi, xa, xb, xc, xd)         \
    Xupdate(f, xi, xa, xb, xc, xd);                                 \
    (f) += (e) + K_20_39 + ROTATE((a), 5) + F_20_39((b), (c), (d)); \
    (b) = ROTATE((b), 30);

#ವ್ಯಾಖ್ಯಾನಿಸು BODY_32_39(i, a, b, c, d, e, f, xa, xb, xc, xd)             \
    Xupdate(f, xa, xa, xb, xc, xd);                                 \
    (f) += (e) + K_20_39 + ROTATE((a), 5) + F_20_39((b), (c), (d)); \
    (b) = ROTATE((b), 30);

#ವ್ಯಾಖ್ಯಾನಿಸು BODY_40_59(i, a, b, c, d, e, f, xa, xb, xc, xd)             \
    Xupdate(f, xa, xa, xb, xc, xd);                                 \
    (f) += (e) + K_40_59 + ROTATE((a), 5) + F_40_59((b), (c), (d)); \
    (b) = ROTATE((b), 30);

#ವ್ಯಾಖ್ಯಾನಿಸು BODY_60_79(i, a, b, c, d, e, f, xa, xb, xc, xd)                 \
    Xupdate(f, xa, xa, xb, xc, xd);                                     \
    (f) = xa + (e) + K_60_79 + ROTATE((a), 5) + F_60_79((b), (c), (d)); \
    (b) = ROTATE((b), 30);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ X
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು X
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ MD32_XARRAY
/*
 * Originally X was an array. As it's automatic it's natural
 * to expect RISC compiler to accommodate at least part of it in
 * the register bank, isn't it? Unfortunately not all compilers
 * "find" this expectation reasonable:-( On order to make such
 * compilers generate better code I replace X[] with a bunch of
 * X0, X1, etc. See the function body below...
 */
#ವ್ಯಾಖ್ಯಾನಿಸು X(i) XX##i
#ಇಲ್ಲದಿದ್ದರೆ
/*
 * However! Some compilers (most notably HP C) get overwhelmed by
 * that many local variables so that we have to have the way to
 * fall down to the original behavior.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು X(i) XX[i]
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(SHA1_ASM)
ಸ್ಥಿರ ಶೂನ್ಯ HASH_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(SHA_CTX *c, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *p, size_t ಅಂಕೆ)
{
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ = p;
    ನೋಂದಣಿ ಚಿಹ್ನೆರಹಿತ MD32_REG_T A, B, C, D, E, T, l;
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ MD32_XARRAY
    ಚಿಹ್ನೆರಹಿತ MD32_REG_T XX0, XX1, XX2, XX3, XX4, XX5, XX6, XX7,
        XX8, XX9, XX10, XX11, XX12, XX13, XX14, XX15;
#ಇಲ್ಲದಿದ್ದರೆ
    SHA_LONG XX[16];
#ಆದರೆ_ಅಂತ್ಯ

    A = c->h0;
    B = c->h1;
    C = c->h2;
    D = c->h3;
    E = c->h4;

    ಗಾಗಿ (;;) {
        DECLARE_IS_ENDIAN;

        ಆದರೆ (!IS_LITTLE_ENDIAN && ಗಾತ್ರ(SHA_LONG) == 4
            && ((size_t)p % 4) == 0) {
            ಸ್ಥಿರಾಂಕ SHA_LONG *W = (ಸ್ಥಿರಾಂಕ SHA_LONG *)ದತ್ತಾಂಶ;

            X(0) = W[0];
            X(1) = W[1];
            BODY_00_15(0, A, B, C, D, E, T, X(0));
            X(2) = W[2];
            BODY_00_15(1, T, A, B, C, D, E, X(1));
            X(3) = W[3];
            BODY_00_15(2, E, T, A, B, C, D, X(2));
            X(4) = W[4];
            BODY_00_15(3, D, E, T, A, B, C, X(3));
            X(5) = W[5];
            BODY_00_15(4, C, D, E, T, A, B, X(4));
            X(6) = W[6];
            BODY_00_15(5, B, C, D, E, T, A, X(5));
            X(7) = W[7];
            BODY_00_15(6, A, B, C, D, E, T, X(6));
            X(8) = W[8];
            BODY_00_15(7, T, A, B, C, D, E, X(7));
            X(9) = W[9];
            BODY_00_15(8, E, T, A, B, C, D, X(8));
            X(10) = W[10];
            BODY_00_15(9, D, E, T, A, B, C, X(9));
            X(11) = W[11];
            BODY_00_15(10, C, D, E, T, A, B, X(10));
            X(12) = W[12];
            BODY_00_15(11, B, C, D, E, T, A, X(11));
            X(13) = W[13];
            BODY_00_15(12, A, B, C, D, E, T, X(12));
            X(14) = W[14];
            BODY_00_15(13, T, A, B, C, D, E, X(13));
            X(15) = W[15];
            BODY_00_15(14, E, T, A, B, C, D, X(14));
            BODY_00_15(15, D, E, T, A, B, C, X(15));

            ದತ್ತಾಂಶ += SHA_CBLOCK;
        } ಇಲ್ಲದಿದ್ದರೆ {
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(0) = l;
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(1) = l;
            BODY_00_15(0, A, B, C, D, E, T, X(0));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(2) = l;
            BODY_00_15(1, T, A, B, C, D, E, X(1));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(3) = l;
            BODY_00_15(2, E, T, A, B, C, D, X(2));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(4) = l;
            BODY_00_15(3, D, E, T, A, B, C, X(3));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(5) = l;
            BODY_00_15(4, C, D, E, T, A, B, X(4));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(6) = l;
            BODY_00_15(5, B, C, D, E, T, A, X(5));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(7) = l;
            BODY_00_15(6, A, B, C, D, E, T, X(6));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(8) = l;
            BODY_00_15(7, T, A, B, C, D, E, X(7));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(9) = l;
            BODY_00_15(8, E, T, A, B, C, D, X(8));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(10) = l;
            BODY_00_15(9, D, E, T, A, B, C, X(9));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(11) = l;
            BODY_00_15(10, C, D, E, T, A, B, X(10));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(12) = l;
            BODY_00_15(11, B, C, D, E, T, A, X(11));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(13) = l;
            BODY_00_15(12, A, B, C, D, E, T, X(12));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(14) = l;
            BODY_00_15(13, T, A, B, C, D, E, X(13));
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X(15) = l;
            BODY_00_15(14, E, T, A, B, C, D, X(14));
            BODY_00_15(15, D, E, T, A, B, C, X(15));
        }

        BODY_16_19(16, C, D, E, T, A, B, X(0), X(0), X(2), X(8), X(13));
        BODY_16_19(17, B, C, D, E, T, A, X(1), X(1), X(3), X(9), X(14));
        BODY_16_19(18, A, B, C, D, E, T, X(2), X(2), X(4), X(10), X(15));
        BODY_16_19(19, T, A, B, C, D, E, X(3), X(3), X(5), X(11), X(0));

        BODY_20_31(20, E, T, A, B, C, D, X(4), X(4), X(6), X(12), X(1));
        BODY_20_31(21, D, E, T, A, B, C, X(5), X(5), X(7), X(13), X(2));
        BODY_20_31(22, C, D, E, T, A, B, X(6), X(6), X(8), X(14), X(3));
        BODY_20_31(23, B, C, D, E, T, A, X(7), X(7), X(9), X(15), X(4));
        BODY_20_31(24, A, B, C, D, E, T, X(8), X(8), X(10), X(0), X(5));
        BODY_20_31(25, T, A, B, C, D, E, X(9), X(9), X(11), X(1), X(6));
        BODY_20_31(26, E, T, A, B, C, D, X(10), X(10), X(12), X(2), X(7));
        BODY_20_31(27, D, E, T, A, B, C, X(11), X(11), X(13), X(3), X(8));
        BODY_20_31(28, C, D, E, T, A, B, X(12), X(12), X(14), X(4), X(9));
        BODY_20_31(29, B, C, D, E, T, A, X(13), X(13), X(15), X(5), X(10));
        BODY_20_31(30, A, B, C, D, E, T, X(14), X(14), X(0), X(6), X(11));
        BODY_20_31(31, T, A, B, C, D, E, X(15), X(15), X(1), X(7), X(12));

        BODY_32_39(32, E, T, A, B, C, D, X(0), X(2), X(8), X(13));
        BODY_32_39(33, D, E, T, A, B, C, X(1), X(3), X(9), X(14));
        BODY_32_39(34, C, D, E, T, A, B, X(2), X(4), X(10), X(15));
        BODY_32_39(35, B, C, D, E, T, A, X(3), X(5), X(11), X(0));
        BODY_32_39(36, A, B, C, D, E, T, X(4), X(6), X(12), X(1));
        BODY_32_39(37, T, A, B, C, D, E, X(5), X(7), X(13), X(2));
        BODY_32_39(38, E, T, A, B, C, D, X(6), X(8), X(14), X(3));
        BODY_32_39(39, D, E, T, A, B, C, X(7), X(9), X(15), X(4));

        BODY_40_59(40, C, D, E, T, A, B, X(8), X(10), X(0), X(5));
        BODY_40_59(41, B, C, D, E, T, A, X(9), X(11), X(1), X(6));
        BODY_40_59(42, A, B, C, D, E, T, X(10), X(12), X(2), X(7));
        BODY_40_59(43, T, A, B, C, D, E, X(11), X(13), X(3), X(8));
        BODY_40_59(44, E, T, A, B, C, D, X(12), X(14), X(4), X(9));
        BODY_40_59(45, D, E, T, A, B, C, X(13), X(15), X(5), X(10));
        BODY_40_59(46, C, D, E, T, A, B, X(14), X(0), X(6), X(11));
        BODY_40_59(47, B, C, D, E, T, A, X(15), X(1), X(7), X(12));
        BODY_40_59(48, A, B, C, D, E, T, X(0), X(2), X(8), X(13));
        BODY_40_59(49, T, A, B, C, D, E, X(1), X(3), X(9), X(14));
        BODY_40_59(50, E, T, A, B, C, D, X(2), X(4), X(10), X(15));
        BODY_40_59(51, D, E, T, A, B, C, X(3), X(5), X(11), X(0));
        BODY_40_59(52, C, D, E, T, A, B, X(4), X(6), X(12), X(1));
        BODY_40_59(53, B, C, D, E, T, A, X(5), X(7), X(13), X(2));
        BODY_40_59(54, A, B, C, D, E, T, X(6), X(8), X(14), X(3));
        BODY_40_59(55, T, A, B, C, D, E, X(7), X(9), X(15), X(4));
        BODY_40_59(56, E, T, A, B, C, D, X(8), X(10), X(0), X(5));
        BODY_40_59(57, D, E, T, A, B, C, X(9), X(11), X(1), X(6));
        BODY_40_59(58, C, D, E, T, A, B, X(10), X(12), X(2), X(7));
        BODY_40_59(59, B, C, D, E, T, A, X(11), X(13), X(3), X(8));

        BODY_60_79(60, A, B, C, D, E, T, X(12), X(14), X(4), X(9));
        BODY_60_79(61, T, A, B, C, D, E, X(13), X(15), X(5), X(10));
        BODY_60_79(62, E, T, A, B, C, D, X(14), X(0), X(6), X(11));
        BODY_60_79(63, D, E, T, A, B, C, X(15), X(1), X(7), X(12));
        BODY_60_79(64, C, D, E, T, A, B, X(0), X(2), X(8), X(13));
        BODY_60_79(65, B, C, D, E, T, A, X(1), X(3), X(9), X(14));
        BODY_60_79(66, A, B, C, D, E, T, X(2), X(4), X(10), X(15));
        BODY_60_79(67, T, A, B, C, D, E, X(3), X(5), X(11), X(0));
        BODY_60_79(68, E, T, A, B, C, D, X(4), X(6), X(12), X(1));
        BODY_60_79(69, D, E, T, A, B, C, X(5), X(7), X(13), X(2));
        BODY_60_79(70, C, D, E, T, A, B, X(6), X(8), X(14), X(3));
        BODY_60_79(71, B, C, D, E, T, A, X(7), X(9), X(15), X(4));
        BODY_60_79(72, A, B, C, D, E, T, X(8), X(10), X(0), X(5));
        BODY_60_79(73, T, A, B, C, D, E, X(9), X(11), X(1), X(6));
        BODY_60_79(74, E, T, A, B, C, D, X(10), X(12), X(2), X(7));
        BODY_60_79(75, D, E, T, A, B, C, X(11), X(13), X(3), X(8));
        BODY_60_79(76, C, D, E, T, A, B, X(12), X(14), X(4), X(9));
        BODY_60_79(77, B, C, D, E, T, A, X(13), X(15), X(5), X(10));
        BODY_60_79(78, A, B, C, D, E, T, X(14), X(0), X(6), X(11));
        BODY_60_79(79, T, A, B, C, D, E, X(15), X(1), X(7), X(12));

        c->h0 = (c->h0 + E) & 0xffffffffL;
        c->h1 = (c->h1 + T) & 0xffffffffL;
        c->h2 = (c->h2 + A) & 0xffffffffL;
        c->h3 = (c->h3 + B) & 0xffffffffL;
        c->h4 = (c->h4 + C) & 0xffffffffL;

        ಆದರೆ (--ಅಂಕೆ == 0)
            ನಿಲ್ಲಿಸು;

        A = c->h0;
        B = c->h1;
        C = c->h2;
        D = c->h3;
        E = c->h4;
    }
}
#ಆದರೆ_ಅಂತ್ಯ

#ಇಲ್ಲದಿದ್ದರೆ /* OPENSSL_SMALL_FOOTPRINT */

#ವ್ಯಾಖ್ಯಾನಿಸು BODY_00_15(xi)                          \
    ಮಾಡು {                                        \
        T = E + K_00_19 + F_00_19(B, C, D);     \
        E = D, D = C, C = ROTATE(B, 30), B = A; \
        A = ROTATE(A, 5) + T + xi;              \
    } ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು BODY_16_19(xa, xb, xc, xd)              \
    ಮಾಡು {                                        \
        Xupdate(T, xa, xa, xb, xc, xd);         \
        T += E + K_00_19 + F_00_19(B, C, D);    \
        E = D, D = C, C = ROTATE(B, 30), B = A; \
        A = ROTATE(A, 5) + T;                   \
    } ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು BODY_20_39(xa, xb, xc, xd)              \
    ಮಾಡು {                                        \
        Xupdate(T, xa, xa, xb, xc, xd);         \
        T += E + K_20_39 + F_20_39(B, C, D);    \
        E = D, D = C, C = ROTATE(B, 30), B = A; \
        A = ROTATE(A, 5) + T;                   \
    } ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು BODY_40_59(xa, xb, xc, xd)              \
    ಮಾಡು {                                        \
        Xupdate(T, xa, xa, xb, xc, xd);         \
        T += E + K_40_59 + F_40_59(B, C, D);    \
        E = D, D = C, C = ROTATE(B, 30), B = A; \
        A = ROTATE(A, 5) + T;                   \
    } ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು BODY_60_79(xa, xb, xc, xd)              \
    ಮಾಡು {                                        \
        Xupdate(T, xa, xa, xb, xc, xd);         \
        T = E + K_60_79 + F_60_79(B, C, D);     \
        E = D, D = C, C = ROTATE(B, 30), B = A; \
        A = ROTATE(A, 5) + T + xa;              \
    } ಆಗ (0)

#ಆದರೆ !defined(SHA1_ASM)
ಸ್ಥಿರ ಶೂನ್ಯ HASH_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(SHA_CTX *c, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *p, size_t ಅಂಕೆ)
{
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ = p;
    ನೋಂದಣಿ ಚಿಹ್ನೆರಹಿತ MD32_REG_T A, B, C, D, E, T, l;
    ಪೂರ್ಣಾಂಕ i;
    SHA_LONG X[16];

    A = c->h0;
    B = c->h1;
    C = c->h2;
    D = c->h3;
    E = c->h4;

    ಗಾಗಿ (;;) {
        ಗಾಗಿ (i = 0; i < 16; i++) {
            (ಶೂನ್ಯ)HOST_c2l(ದತ್ತಾಂಶ, l);
            X[i] = l;
            BODY_00_15(X[i]);
        }
        ಗಾಗಿ (i = 0; i < 4; i++) {
            BODY_16_19(X[i], X[i + 2], X[i + 8], X[(i + 13) & 15]);
        }
        ಗಾಗಿ (; i < 24; i++) {
            BODY_20_39(X[i & 15], X[(i + 2) & 15], X[(i + 8) & 15],
                X[(i + 13) & 15]);
        }
        ಗಾಗಿ (i = 0; i < 20; i++) {
            BODY_40_59(X[(i + 8) & 15], X[(i + 10) & 15], X[i & 15],
                X[(i + 5) & 15]);
        }
        ಗಾಗಿ (i = 4; i < 24; i++) {
            BODY_60_79(X[(i + 8) & 15], X[(i + 10) & 15], X[i & 15],
                X[(i + 5) & 15]);
        }

        c->h0 = (c->h0 + A) & 0xffffffffL;
        c->h1 = (c->h1 + B) & 0xffffffffL;
        c->h2 = (c->h2 + C) & 0xffffffffL;
        c->h3 = (c->h3 + D) & 0xffffffffL;
        c->h4 = (c->h4 + E) & 0xffffffffL;

        ಆದರೆ (--ಅಂಕೆ == 0)
            ನಿಲ್ಲಿಸು;

        A = c->h0;
        B = c->h1;
        C = c->h2;
        D = c->h3;
        E = c->h4;
    }
}
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* !defined(OSSL_LIBCRYPTO_SHA_SHA_LOCAL_H) */
