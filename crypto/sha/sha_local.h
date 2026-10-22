/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#अगर !defined(OSSL_LIBCRYPTO_SHA_SHA_LOCAL_H)
#घोषणा OSSL_LIBCRYPTO_SHA_SHA_LOCAL_H

#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश <openssl/opensslconf.h>
#समावेश <openssl/sha.h>
#समावेश "internal/endian.h"

#घोषणा तथ्य_ORDER_IS_BIG_ENDIAN

#घोषणा HASH_LONG SHA_LONG
#घोषणा HASH_CTX SHA_CTX
#घोषणा HASH_CBLOCK SHA_CBLOCK
#घोषणा HASH_MAKE_STRING(c, s)   \
    करो {                         \
        अचिन्हित दीर्घ ll;        \
        ll = (c)->h0;            \
        (व्योम)HOST_l2c(ll, (s)); \
        ll = (c)->h1;            \
        (व्योम)HOST_l2c(ll, (s)); \
        ll = (c)->h2;            \
        (व्योम)HOST_l2c(ll, (s)); \
        ll = (c)->h3;            \
        (व्योम)HOST_l2c(ll, (s)); \
        ll = (c)->h4;            \
        (व्योम)HOST_l2c(ll, (s)); \
    } जबतक (0)

#घोषणा HASH_UPDATE_THUNK
#घोषणा HASH_UPDATE SHA1_Update_thunk
#घोषणा HASH_TRANSFORM SHA1_Transform
#घोषणा HASH_FINAL SHA1_Final
#घोषणा HASH_INIT SHA1_Init
#घोषणा HASH_BLOCK_तथ्य_ORDER sha1_block_तथ्य_order
#घोषणा Xupdate(a, ix, ia, ib, ic, id) ((a) = (ia ^ ib ^ ic ^ id), \
    ix = (a) = ROTATE((a), 1))

#अगर_अघोषित SHA1_ASM
अटल व्योम sha1_block_तथ्य_order(SHA_CTX *c, स्थिर व्योम *p, माप_प्रकार अंक);
#अन्यथा
व्योम sha1_block_तथ्य_order(SHA_CTX *c, स्थिर व्योम *p, माप_प्रकार अंक);
#पूर्ण_अगर

/* clang-format off */
#समावेश "crypto/md32_common.inc"
/* clang-format on */
#अघोषित HASH_UPDATE_THUNK

पूर्णांक SHA1_Update(SHA_CTX *c, स्थिर व्योम *तथ्य, माप_प्रकार len)
{
    वापस SHA1_Update_thunk((व्योम *)c, (स्थिर अचिन्हित अक्षर *)तथ्य, len);
}

#घोषणा INIT_तथ्य_h0 0x67452301UL
#घोषणा INIT_तथ्य_h1 0xefcdab89UL
#घोषणा INIT_तथ्य_h2 0x98badcfeUL
#घोषणा INIT_तथ्य_h3 0x10325476UL
#घोषणा INIT_तथ्य_h4 0xc3d2e1f0UL

पूर्णांक HASH_INIT(SHA_CTX *c)
{
    स_रखो(c, 0, माप(*c));
    c->h0 = INIT_तथ्य_h0;
    c->h1 = INIT_तथ्य_h1;
    c->h2 = INIT_तथ्य_h2;
    c->h3 = INIT_तथ्य_h3;
    c->h4 = INIT_तथ्य_h4;
    वापस 1;
}

#घोषणा K_00_19 0x5a827999UL
#घोषणा K_20_39 0x6ed9eba1UL
#घोषणा K_40_59 0x8f1bbcdcUL
#घोषणा K_60_79 0xca62c1d6UL

/*
 * As pointed out by Wei Dai, F() below can be simplified to the code in
 * F_00_19.  Wei attributes these optimizations to Peter Gutmann's SHS code,
 * and he attributes it to Rich Schroeppel.
 *      #define F(x,y,z) (((x) & (y)) | ((~(x)) & (z)))
 * I've just become aware of another tweak to be made, again from Wei Dai,
 * in F_40_59, (x&a)|(y&a) -> (x|y)&a
 */
#घोषणा F_00_19(b, c, d) ((((c) ^ (d)) & (b)) ^ (d))
#घोषणा F_20_39(b, c, d) ((b) ^ (c) ^ (d))
#घोषणा F_40_59(b, c, d) (((b) & (c)) | (((b) | (c)) & (d)))
#घोषणा F_60_79(b, c, d) F_20_39(b, c, d)

#अगर_अघोषित OPENSSL_SMALL_FOOTPRINT

#घोषणा BODY_00_15(i, a, b, c, d, e, f, xi)                             \
    (f) = xi + (e) + K_00_19 + ROTATE((a), 5) + F_00_19((b), (c), (d)); \
    (b) = ROTATE((b), 30);

#घोषणा BODY_16_19(i, a, b, c, d, e, f, xi, xa, xb, xc, xd)         \
    Xupdate(f, xi, xa, xb, xc, xd);                                 \
    (f) += (e) + K_00_19 + ROTATE((a), 5) + F_00_19((b), (c), (d)); \
    (b) = ROTATE((b), 30);

#घोषणा BODY_20_31(i, a, b, c, d, e, f, xi, xa, xb, xc, xd)         \
    Xupdate(f, xi, xa, xb, xc, xd);                                 \
    (f) += (e) + K_20_39 + ROTATE((a), 5) + F_20_39((b), (c), (d)); \
    (b) = ROTATE((b), 30);

#घोषणा BODY_32_39(i, a, b, c, d, e, f, xa, xb, xc, xd)             \
    Xupdate(f, xa, xa, xb, xc, xd);                                 \
    (f) += (e) + K_20_39 + ROTATE((a), 5) + F_20_39((b), (c), (d)); \
    (b) = ROTATE((b), 30);

#घोषणा BODY_40_59(i, a, b, c, d, e, f, xa, xb, xc, xd)             \
    Xupdate(f, xa, xa, xb, xc, xd);                                 \
    (f) += (e) + K_40_59 + ROTATE((a), 5) + F_40_59((b), (c), (d)); \
    (b) = ROTATE((b), 30);

#घोषणा BODY_60_79(i, a, b, c, d, e, f, xa, xb, xc, xd)                 \
    Xupdate(f, xa, xa, xb, xc, xd);                                     \
    (f) = xa + (e) + K_60_79 + ROTATE((a), 5) + F_60_79((b), (c), (d)); \
    (b) = ROTATE((b), 30);

#अगर_घोषित X
#अघोषित X
#पूर्ण_अगर
#अगर_अघोषित MD32_XARRAY
/*
 * Originally X was an array. As it's automatic it's natural
 * to expect RISC compiler to accommodate at least part of it in
 * the register bank, isn't it? Unfortunately not all compilers
 * "find" this expectation reasonable:-( On order to make such
 * compilers generate better code I replace X[] with a bunch of
 * X0, X1, etc. See the function body below...
 */
#घोषणा X(i) XX##i
#अन्यथा
/*
 * However! Some compilers (most notably HP C) get overwhelmed by
 * that many local variables so that we have to have the way to
 * fall down to the original behavior.
 */
#घोषणा X(i) XX[i]
#पूर्ण_अगर

#अगर !defined(SHA1_ASM)
अटल व्योम HASH_BLOCK_तथ्य_ORDER(SHA_CTX *c, स्थिर व्योम *p, माप_प्रकार अंक)
{
    स्थिर अचिन्हित अक्षर *तथ्य = p;
    रेजिस्टर अचिन्हित MD32_REG_T A, B, C, D, E, T, l;
#अगर_अघोषित MD32_XARRAY
    अचिन्हित MD32_REG_T XX0, XX1, XX2, XX3, XX4, XX5, XX6, XX7,
        XX8, XX9, XX10, XX11, XX12, XX13, XX14, XX15;
#अन्यथा
    SHA_LONG XX[16];
#पूर्ण_अगर

    A = c->h0;
    B = c->h1;
    C = c->h2;
    D = c->h3;
    E = c->h4;

    क्रम (;;) {
        DECLARE_IS_ENDIAN;

        अगर (!IS_LITTLE_ENDIAN && माप(SHA_LONG) == 4
            && ((माप_प्रकार)p % 4) == 0) {
            स्थिर SHA_LONG *W = (स्थिर SHA_LONG *)तथ्य;

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

            तथ्य += SHA_CBLOCK;
        } अन्यथा {
            (व्योम)HOST_c2l(तथ्य, l);
            X(0) = l;
            (व्योम)HOST_c2l(तथ्य, l);
            X(1) = l;
            BODY_00_15(0, A, B, C, D, E, T, X(0));
            (व्योम)HOST_c2l(तथ्य, l);
            X(2) = l;
            BODY_00_15(1, T, A, B, C, D, E, X(1));
            (व्योम)HOST_c2l(तथ्य, l);
            X(3) = l;
            BODY_00_15(2, E, T, A, B, C, D, X(2));
            (व्योम)HOST_c2l(तथ्य, l);
            X(4) = l;
            BODY_00_15(3, D, E, T, A, B, C, X(3));
            (व्योम)HOST_c2l(तथ्य, l);
            X(5) = l;
            BODY_00_15(4, C, D, E, T, A, B, X(4));
            (व्योम)HOST_c2l(तथ्य, l);
            X(6) = l;
            BODY_00_15(5, B, C, D, E, T, A, X(5));
            (व्योम)HOST_c2l(तथ्य, l);
            X(7) = l;
            BODY_00_15(6, A, B, C, D, E, T, X(6));
            (व्योम)HOST_c2l(तथ्य, l);
            X(8) = l;
            BODY_00_15(7, T, A, B, C, D, E, X(7));
            (व्योम)HOST_c2l(तथ्य, l);
            X(9) = l;
            BODY_00_15(8, E, T, A, B, C, D, X(8));
            (व्योम)HOST_c2l(तथ्य, l);
            X(10) = l;
            BODY_00_15(9, D, E, T, A, B, C, X(9));
            (व्योम)HOST_c2l(तथ्य, l);
            X(11) = l;
            BODY_00_15(10, C, D, E, T, A, B, X(10));
            (व्योम)HOST_c2l(तथ्य, l);
            X(12) = l;
            BODY_00_15(11, B, C, D, E, T, A, X(11));
            (व्योम)HOST_c2l(तथ्य, l);
            X(13) = l;
            BODY_00_15(12, A, B, C, D, E, T, X(12));
            (व्योम)HOST_c2l(तथ्य, l);
            X(14) = l;
            BODY_00_15(13, T, A, B, C, D, E, X(13));
            (व्योम)HOST_c2l(तथ्य, l);
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

        अगर (--अंक == 0)
            अवरोध;

        A = c->h0;
        B = c->h1;
        C = c->h2;
        D = c->h3;
        E = c->h4;
    }
}
#पूर्ण_अगर

#अन्यथा /* OPENSSL_SMALL_FOOTPRINT */

#घोषणा BODY_00_15(xi)                          \
    करो {                                        \
        T = E + K_00_19 + F_00_19(B, C, D);     \
        E = D, D = C, C = ROTATE(B, 30), B = A; \
        A = ROTATE(A, 5) + T + xi;              \
    } जबतक (0)

#घोषणा BODY_16_19(xa, xb, xc, xd)              \
    करो {                                        \
        Xupdate(T, xa, xa, xb, xc, xd);         \
        T += E + K_00_19 + F_00_19(B, C, D);    \
        E = D, D = C, C = ROTATE(B, 30), B = A; \
        A = ROTATE(A, 5) + T;                   \
    } जबतक (0)

#घोषणा BODY_20_39(xa, xb, xc, xd)              \
    करो {                                        \
        Xupdate(T, xa, xa, xb, xc, xd);         \
        T += E + K_20_39 + F_20_39(B, C, D);    \
        E = D, D = C, C = ROTATE(B, 30), B = A; \
        A = ROTATE(A, 5) + T;                   \
    } जबतक (0)

#घोषणा BODY_40_59(xa, xb, xc, xd)              \
    करो {                                        \
        Xupdate(T, xa, xa, xb, xc, xd);         \
        T += E + K_40_59 + F_40_59(B, C, D);    \
        E = D, D = C, C = ROTATE(B, 30), B = A; \
        A = ROTATE(A, 5) + T;                   \
    } जबतक (0)

#घोषणा BODY_60_79(xa, xb, xc, xd)              \
    करो {                                        \
        Xupdate(T, xa, xa, xb, xc, xd);         \
        T = E + K_60_79 + F_60_79(B, C, D);     \
        E = D, D = C, C = ROTATE(B, 30), B = A; \
        A = ROTATE(A, 5) + T + xa;              \
    } जबतक (0)

#अगर !defined(SHA1_ASM)
अटल व्योम HASH_BLOCK_तथ्य_ORDER(SHA_CTX *c, स्थिर व्योम *p, माप_प्रकार अंक)
{
    स्थिर अचिन्हित अक्षर *तथ्य = p;
    रेजिस्टर अचिन्हित MD32_REG_T A, B, C, D, E, T, l;
    पूर्णांक i;
    SHA_LONG X[16];

    A = c->h0;
    B = c->h1;
    C = c->h2;
    D = c->h3;
    E = c->h4;

    क्रम (;;) {
        क्रम (i = 0; i < 16; i++) {
            (व्योम)HOST_c2l(तथ्य, l);
            X[i] = l;
            BODY_00_15(X[i]);
        }
        क्रम (i = 0; i < 4; i++) {
            BODY_16_19(X[i], X[i + 2], X[i + 8], X[(i + 13) & 15]);
        }
        क्रम (; i < 24; i++) {
            BODY_20_39(X[i & 15], X[(i + 2) & 15], X[(i + 8) & 15],
                X[(i + 13) & 15]);
        }
        क्रम (i = 0; i < 20; i++) {
            BODY_40_59(X[(i + 8) & 15], X[(i + 10) & 15], X[i & 15],
                X[(i + 5) & 15]);
        }
        क्रम (i = 4; i < 24; i++) {
            BODY_60_79(X[(i + 8) & 15], X[(i + 10) & 15], X[i & 15],
                X[(i + 5) & 15]);
        }

        c->h0 = (c->h0 + A) & 0xffffffffL;
        c->h1 = (c->h1 + B) & 0xffffffffL;
        c->h2 = (c->h2 + C) & 0xffffffffL;
        c->h3 = (c->h3 + D) & 0xffffffffL;
        c->h4 = (c->h4 + E) & 0xffffffffL;

        अगर (--अंक == 0)
            अवरोध;

        A = c->h0;
        B = c->h1;
        C = c->h2;
        D = c->h3;
        E = c->h4;
    }
}
#पूर्ण_अगर

#पूर्ण_अगर

#पूर्ण_अगर /* !defined(OSSL_LIBCRYPTO_SHA_SHA_LOCAL_H) */
