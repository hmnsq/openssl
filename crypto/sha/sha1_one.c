/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * SHA-1 low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#અન્તર્ભાવ "internal/deprecated.h"

#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <openssl/crypto.h>
#અન્તર્ભાવ <openssl/sha.h>
#અન્તર્ભાવ <openssl/evp.h>
#અન્તર્ભાવ "crypto/sha.h"

unsigned અક્ષર *ossl_sha1(અચલ unsigned અક્ષર *d, size_t n, unsigned અક્ષર *md)
{
    SHA_CTX c;
    સ્થિર unsigned અક્ષર m[SHA_DIGEST_LENGTH];

    જો (md == ખાલી)
        md = m;
    જો (!SHA1_Init(&c))
        પાછા ખાલી;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, કદ(c));
    પાછા md;
}

unsigned અક્ષર *SHA1(અચલ unsigned અક્ષર *d, size_t n, unsigned અક્ષર *md)
{
    સ્થિર unsigned અક્ષર m[SHA_DIGEST_LENGTH];

    જો (md == ખાલી)
        md = m;
    પાછા EVP_Q_digest(ખાલી, "SHA1", ખાલી, d, n, md, ખાલી) ? md : ખાલી;
}

unsigned અક્ષર *SHA224(અચલ unsigned અક્ષર *d, size_t n, unsigned અક્ષર *md)
{
    સ્થિર unsigned અક્ષર m[SHA224_DIGEST_LENGTH];

    જો (md == ખાલી)
        md = m;
    પાછા EVP_Q_digest(ખાલી, "SHA224", ખાલી, d, n, md, ખાલી) ? md : ખાલી;
}

unsigned અક્ષર *SHA256(અચલ unsigned અક્ષર *d, size_t n, unsigned અક્ષર *md)
{
    સ્થિર unsigned અક્ષર m[SHA256_DIGEST_LENGTH];

    જો (md == ખાલી)
        md = m;
    પાછા EVP_Q_digest(ખાલી, "SHA256", ખાલી, d, n, md, ખાલી) ? md : ખાલી;
}

unsigned અક્ષર *SHA384(અચલ unsigned અક્ષર *d, size_t n, unsigned અક્ષર *md)
{
    સ્થિર unsigned અક્ષર m[SHA384_DIGEST_LENGTH];

    જો (md == ખાલી)
        md = m;
    પાછા EVP_Q_digest(ખાલી, "SHA384", ખાલી, d, n, md, ખાલી) ? md : ખાલી;
}

unsigned અક્ષર *SHA512(અચલ unsigned અક્ષર *d, size_t n, unsigned અક્ષર *md)
{
    સ્થિર unsigned અક્ષર m[SHA512_DIGEST_LENGTH];

    જો (md == ખાલી)
        md = m;
    પાછા EVP_Q_digest(ખાલી, "SHA512", ખાલી, d, n, md, ખાલી) ? md : ખાલી;
}
