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
#অন্তর্ভাব "internal/deprecated.h"

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <openssl/crypto.h>
#অন্তর্ভাব <openssl/sha.h>
#অন্তর্ভাব <openssl/evp.h>
#অন্তর্ভাব "crypto/sha.h"

unsigned অক্ষর *ossl_sha1(ধ্রুবক unsigned অক্ষর *d, size_t n, unsigned অক্ষর *md)
{
    SHA_CTX c;
    স্থির unsigned অক্ষর m[SHA_DIGEST_দৈর্ঘ্য];

    যদি (md == ফাঁকা)
        md = m;
    যদি (!SHA1_Init(&c))
        ফেরত ফাঁকা;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, আকার(c));
    ফেরত md;
}

unsigned অক্ষর *SHA1(ধ্রুবক unsigned অক্ষর *d, size_t n, unsigned অক্ষর *md)
{
    স্থির unsigned অক্ষর m[SHA_DIGEST_দৈর্ঘ্য];

    যদি (md == ফাঁকা)
        md = m;
    ফেরত EVP_Q_digest(ফাঁকা, "SHA1", ফাঁকা, d, n, md, ফাঁকা) ? md : ফাঁকা;
}

unsigned অক্ষর *SHA224(ধ্রুবক unsigned অক্ষর *d, size_t n, unsigned অক্ষর *md)
{
    স্থির unsigned অক্ষর m[SHA224_DIGEST_দৈর্ঘ্য];

    যদি (md == ফাঁকা)
        md = m;
    ফেরত EVP_Q_digest(ফাঁকা, "SHA224", ফাঁকা, d, n, md, ফাঁকা) ? md : ফাঁকা;
}

unsigned অক্ষর *SHA256(ধ্রুবক unsigned অক্ষর *d, size_t n, unsigned অক্ষর *md)
{
    স্থির unsigned অক্ষর m[SHA256_DIGEST_দৈর্ঘ্য];

    যদি (md == ফাঁকা)
        md = m;
    ফেরত EVP_Q_digest(ফাঁকা, "SHA256", ফাঁকা, d, n, md, ফাঁকা) ? md : ফাঁকা;
}

unsigned অক্ষর *SHA384(ধ্রুবক unsigned অক্ষর *d, size_t n, unsigned অক্ষর *md)
{
    স্থির unsigned অক্ষর m[SHA384_DIGEST_দৈর্ঘ্য];

    যদি (md == ফাঁকা)
        md = m;
    ফেরত EVP_Q_digest(ফাঁকা, "SHA384", ফাঁকা, d, n, md, ফাঁকা) ? md : ফাঁকা;
}

unsigned অক্ষর *SHA512(ধ্রুবক unsigned অক্ষর *d, size_t n, unsigned অক্ষর *md)
{
    স্থির unsigned অক্ষর m[SHA512_DIGEST_দৈর্ঘ্য];

    যদি (md == ফাঁকা)
        md = m;
    ফেরত EVP_Q_digest(ফাঁকা, "SHA512", ফাঁকা, d, n, md, ফাঁকা) ? md : ফাঁকা;
}
