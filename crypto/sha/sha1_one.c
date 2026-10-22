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

unsigned বর্ণ *ossl_sha1(ধ্রুব unsigned বর্ণ *d, size_t n, unsigned বর্ণ *md)
{
    SHA_CTX c;
    স্থির unsigned বর্ণ m[SHA_DIGEST_LENGTH];

    যদি (md == রিক্ত)
        md = m;
    যদি (!SHA1_Init(&c))
        প্রত্যাগম রিক্ত;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, পরিমাণ(c));
    প্রত্যাগম md;
}

unsigned বর্ণ *SHA1(ধ্রুব unsigned বর্ণ *d, size_t n, unsigned বর্ণ *md)
{
    স্থির unsigned বর্ণ m[SHA_DIGEST_LENGTH];

    যদি (md == রিক্ত)
        md = m;
    প্রত্যাগম EVP_Q_digest(রিক্ত, "SHA1", রিক্ত, d, n, md, রিক্ত) ? md : রিক্ত;
}

unsigned বর্ণ *SHA224(ধ্রুব unsigned বর্ণ *d, size_t n, unsigned বর্ণ *md)
{
    স্থির unsigned বর্ণ m[SHA224_DIGEST_LENGTH];

    যদি (md == রিক্ত)
        md = m;
    প্রত্যাগম EVP_Q_digest(রিক্ত, "SHA224", রিক্ত, d, n, md, রিক্ত) ? md : রিক্ত;
}

unsigned বর্ণ *SHA256(ধ্রুব unsigned বর্ণ *d, size_t n, unsigned বর্ণ *md)
{
    স্থির unsigned বর্ণ m[SHA256_DIGEST_LENGTH];

    যদি (md == রিক্ত)
        md = m;
    প্রত্যাগম EVP_Q_digest(রিক্ত, "SHA256", রিক্ত, d, n, md, রিক্ত) ? md : রিক্ত;
}

unsigned বর্ণ *SHA384(ধ্রুব unsigned বর্ণ *d, size_t n, unsigned বর্ণ *md)
{
    স্থির unsigned বর্ণ m[SHA384_DIGEST_LENGTH];

    যদি (md == রিক্ত)
        md = m;
    প্রত্যাগম EVP_Q_digest(রিক্ত, "SHA384", রিক্ত, d, n, md, রিক্ত) ? md : রিক্ত;
}

unsigned বর্ণ *SHA512(ধ্রুব unsigned বর্ণ *d, size_t n, unsigned বর্ণ *md)
{
    স্থির unsigned বর্ণ m[SHA512_DIGEST_LENGTH];

    যদি (md == রিক্ত)
        md = m;
    প্রত্যাগম EVP_Q_digest(রিক্ত, "SHA512", রিক্ত, d, n, md, রিক্ত) ? md : রিক্ত;
}
