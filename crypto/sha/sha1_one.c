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
#ਅਨ੍ਤਰ੍ਭਾਵ "internal/deprecated.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/crypto.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/sha.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "crypto/sha.h"

ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ossl_sha1(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *d, size_t n, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *md)
{
    SHA_CTX c;
    ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ m[SHA_DIGEST_ਲੰਮਾਈ];

    ਜੇ (md == ਨਿਰਾ)
        md = m;
    ਜੇ (!SHA1_Init(&c))
        ਵਾਪਸ ਨਿਰਾ;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, ਆਕਾਰ(c));
    ਵਾਪਸ md;
}

ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *SHA1(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *d, size_t n, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *md)
{
    ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ m[SHA_DIGEST_ਲੰਮਾਈ];

    ਜੇ (md == ਨਿਰਾ)
        md = m;
    ਵਾਪਸ EVP_Q_digest(ਨਿਰਾ, "SHA1", ਨਿਰਾ, d, n, md, ਨਿਰਾ) ? md : ਨਿਰਾ;
}

ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *SHA224(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *d, size_t n, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *md)
{
    ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ m[SHA224_DIGEST_ਲੰਮਾਈ];

    ਜੇ (md == ਨਿਰਾ)
        md = m;
    ਵਾਪਸ EVP_Q_digest(ਨਿਰਾ, "SHA224", ਨਿਰਾ, d, n, md, ਨਿਰਾ) ? md : ਨਿਰਾ;
}

ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *SHA256(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *d, size_t n, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *md)
{
    ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ m[SHA256_DIGEST_ਲੰਮਾਈ];

    ਜੇ (md == ਨਿਰਾ)
        md = m;
    ਵਾਪਸ EVP_Q_digest(ਨਿਰਾ, "SHA256", ਨਿਰਾ, d, n, md, ਨਿਰਾ) ? md : ਨਿਰਾ;
}

ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *SHA384(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *d, size_t n, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *md)
{
    ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ m[SHA384_DIGEST_ਲੰਮਾਈ];

    ਜੇ (md == ਨਿਰਾ)
        md = m;
    ਵਾਪਸ EVP_Q_digest(ਨਿਰਾ, "SHA384", ਨਿਰਾ, d, n, md, ਨਿਰਾ) ? md : ਨਿਰਾ;
}

ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *SHA512(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *d, size_t n, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *md)
{
    ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ m[SHA512_DIGEST_ਲੰਮਾਈ];

    ਜੇ (md == ਨਿਰਾ)
        md = m;
    ਵਾਪਸ EVP_Q_digest(ਨਿਰਾ, "SHA512", ਨਿਰਾ, d, n, md, ਨਿਰਾ) ? md : ਨਿਰਾ;
}
