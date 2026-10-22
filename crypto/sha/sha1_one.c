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
#ଅନ୍ତର୍ଭାଵ "internal/deprecated.h"

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <openssl/crypto.h>
#ଅନ୍ତର୍ଭାଵ <openssl/sha.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#ଅନ୍ତର୍ଭାଵ "crypto/sha.h"

unsigned ଅକ୍ଷର *ossl_sha1(ଅଚଳ unsigned ଅକ୍ଷର *d, size_t n, unsigned ଅକ୍ଷର *md)
{
    SHA_CTX c;
    ସ୍ଥିର unsigned ଅକ୍ଷର m[SHA_DIGEST_LENGTH];

    ଯଦି (md == ଖାଲି)
        md = m;
    ଯଦି (!SHA1_Init(&c))
        ଫେରନ୍ତୁ ଖାଲି;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, ଆକାର(c));
    ଫେରନ୍ତୁ md;
}

unsigned ଅକ୍ଷର *SHA1(ଅଚଳ unsigned ଅକ୍ଷର *d, size_t n, unsigned ଅକ୍ଷର *md)
{
    ସ୍ଥିର unsigned ଅକ୍ଷର m[SHA_DIGEST_LENGTH];

    ଯଦି (md == ଖାଲି)
        md = m;
    ଫେରନ୍ତୁ EVP_Q_digest(ଖାଲି, "SHA1", ଖାଲି, d, n, md, ଖାଲି) ? md : ଖାଲି;
}

unsigned ଅକ୍ଷର *SHA224(ଅଚଳ unsigned ଅକ୍ଷର *d, size_t n, unsigned ଅକ୍ଷର *md)
{
    ସ୍ଥିର unsigned ଅକ୍ଷର m[SHA224_DIGEST_LENGTH];

    ଯଦି (md == ଖାଲି)
        md = m;
    ଫେରନ୍ତୁ EVP_Q_digest(ଖାଲି, "SHA224", ଖାଲି, d, n, md, ଖାଲି) ? md : ଖାଲି;
}

unsigned ଅକ୍ଷର *SHA256(ଅଚଳ unsigned ଅକ୍ଷର *d, size_t n, unsigned ଅକ୍ଷର *md)
{
    ସ୍ଥିର unsigned ଅକ୍ଷର m[SHA256_DIGEST_LENGTH];

    ଯଦି (md == ଖାଲି)
        md = m;
    ଫେରନ୍ତୁ EVP_Q_digest(ଖାଲି, "SHA256", ଖାଲି, d, n, md, ଖାଲି) ? md : ଖାଲି;
}

unsigned ଅକ୍ଷର *SHA384(ଅଚଳ unsigned ଅକ୍ଷର *d, size_t n, unsigned ଅକ୍ଷର *md)
{
    ସ୍ଥିର unsigned ଅକ୍ଷର m[SHA384_DIGEST_LENGTH];

    ଯଦି (md == ଖାଲି)
        md = m;
    ଫେରନ୍ତୁ EVP_Q_digest(ଖାଲି, "SHA384", ଖାଲି, d, n, md, ଖାଲି) ? md : ଖାଲି;
}

unsigned ଅକ୍ଷର *SHA512(ଅଚଳ unsigned ଅକ୍ଷର *d, size_t n, unsigned ଅକ୍ଷର *md)
{
    ସ୍ଥିର unsigned ଅକ୍ଷର m[SHA512_DIGEST_LENGTH];

    ଯଦି (md == ଖାଲି)
        md = m;
    ଫେରନ୍ତୁ EVP_Q_digest(ଖାଲି, "SHA512", ଖାଲି, d, n, md, ଖାଲି) ? md : ଖାଲି;
}
