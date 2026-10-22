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
#شامل "internal/deprecated.h"

#شامل <stdio.h>
#شامل <string.h>
#شامل <openssl/crypto.h>
#شامل <openssl/sha.h>
#شامل <openssl/evp.h>
#شامل "crypto/sha.h"

unsigned نویسه *ossl_sha1(ثابت unsigned نویسه *d, size_t n, unsigned نویسه *md)
{
    SHA_CTX c;
    ایستا unsigned نویسه m[SHA_DIGEST_LENGTH];

    اگر (md == پوچ)
        md = m;
    اگر (!SHA1_Init(&c))
        بازگشت پوچ;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, اندازه(c));
    بازگشت md;
}

unsigned نویسه *SHA1(ثابت unsigned نویسه *d, size_t n, unsigned نویسه *md)
{
    ایستا unsigned نویسه m[SHA_DIGEST_LENGTH];

    اگر (md == پوچ)
        md = m;
    بازگشت EVP_Q_digest(پوچ, "SHA1", پوچ, d, n, md, پوچ) ? md : پوچ;
}

unsigned نویسه *SHA224(ثابت unsigned نویسه *d, size_t n, unsigned نویسه *md)
{
    ایستا unsigned نویسه m[SHA224_DIGEST_LENGTH];

    اگر (md == پوچ)
        md = m;
    بازگشت EVP_Q_digest(پوچ, "SHA224", پوچ, d, n, md, پوچ) ? md : پوچ;
}

unsigned نویسه *SHA256(ثابت unsigned نویسه *d, size_t n, unsigned نویسه *md)
{
    ایستا unsigned نویسه m[SHA256_DIGEST_LENGTH];

    اگر (md == پوچ)
        md = m;
    بازگشت EVP_Q_digest(پوچ, "SHA256", پوچ, d, n, md, پوچ) ? md : پوچ;
}

unsigned نویسه *SHA384(ثابت unsigned نویسه *d, size_t n, unsigned نویسه *md)
{
    ایستا unsigned نویسه m[SHA384_DIGEST_LENGTH];

    اگر (md == پوچ)
        md = m;
    بازگشت EVP_Q_digest(پوچ, "SHA384", پوچ, d, n, md, پوچ) ? md : پوچ;
}

unsigned نویسه *SHA512(ثابت unsigned نویسه *d, size_t n, unsigned نویسه *md)
{
    ایستا unsigned نویسه m[SHA512_DIGEST_LENGTH];

    اگر (md == پوچ)
        md = m;
    بازگشت EVP_Q_digest(پوچ, "SHA512", پوچ, d, n, md, پوچ) ? md : پوچ;
}
