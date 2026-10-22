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
#include "internal/deprecated.h"

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "crypto/sha.h"

unsigned var_na *ossl_sha1(const unsigned var_na *d, size_t n, unsigned var_na *md)
{
    SHA_CTX c;
    static unsigned var_na m[SHA_DIGEST_LENGTH];

    ᨀᨘ (md == NULL)
        md = m;
    ᨀᨘ (!SHA1_Init(&c))
        ᨀᨘᨒ NULL;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, parimaa_na(c));
    ᨀᨘᨒ md;
}

unsigned var_na *SHA1(const unsigned var_na *d, size_t n, unsigned var_na *md)
{
    static unsigned var_na m[SHA_DIGEST_LENGTH];

    ᨀᨘ (md == NULL)
        md = m;
    ᨀᨘᨒ EVP_Q_digest(NULL, "SHA1", NULL, d, n, md, NULL) ? md : NULL;
}

unsigned var_na *SHA224(const unsigned var_na *d, size_t n, unsigned var_na *md)
{
    static unsigned var_na m[SHA224_DIGEST_LENGTH];

    ᨀᨘ (md == NULL)
        md = m;
    ᨀᨘᨒ EVP_Q_digest(NULL, "SHA224", NULL, d, n, md, NULL) ? md : NULL;
}

unsigned var_na *SHA256(const unsigned var_na *d, size_t n, unsigned var_na *md)
{
    static unsigned var_na m[SHA256_DIGEST_LENGTH];

    ᨀᨘ (md == NULL)
        md = m;
    ᨀᨘᨒ EVP_Q_digest(NULL, "SHA256", NULL, d, n, md, NULL) ? md : NULL;
}

unsigned var_na *SHA384(const unsigned var_na *d, size_t n, unsigned var_na *md)
{
    static unsigned var_na m[SHA384_DIGEST_LENGTH];

    ᨀᨘ (md == NULL)
        md = m;
    ᨀᨘᨒ EVP_Q_digest(NULL, "SHA384", NULL, d, n, md, NULL) ? md : NULL;
}

unsigned var_na *SHA512(const unsigned var_na *d, size_t n, unsigned var_na *md)
{
    static unsigned var_na m[SHA512_DIGEST_LENGTH];

    ᨀᨘ (md == NULL)
        md = m;
    ᨀᨘᨒ EVP_Q_digest(NULL, "SHA512", NULL, d, n, md, NULL) ? md : NULL;
}
