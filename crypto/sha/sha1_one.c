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
#অন্তর্ভাৱ "internal/deprecated.h"

#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <openssl/crypto.h>
#অন্তর্ভাৱ <openssl/sha.h>
#অন্তর্ভাৱ <openssl/evp.h>
#অন্তর্ভাৱ "crypto/sha.h"

unsigned ৱর্ণ *ossl_sha1(ধ্রুৱ unsigned ৱর্ণ *d, size_t n, unsigned ৱর্ণ *md)
{
    SHA_CTX c;
    স্থির unsigned ৱর্ণ m[SHA_DIGEST_LENGTH];

    যদি (md == রিক্ত)
        md = m;
    যদি (!SHA1_Init(&c))
        ঘূৰাই রিক্ত;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, পরিমাণ(c));
    ঘূৰাই md;
}

unsigned ৱর্ণ *SHA1(ধ্রুৱ unsigned ৱর্ণ *d, size_t n, unsigned ৱর্ণ *md)
{
    স্থির unsigned ৱর্ণ m[SHA_DIGEST_LENGTH];

    যদি (md == রিক্ত)
        md = m;
    ঘূৰাই EVP_Q_digest(রিক্ত, "SHA1", রিক্ত, d, n, md, রিক্ত) ? md : রিক্ত;
}

unsigned ৱর্ণ *SHA224(ধ্রুৱ unsigned ৱর্ণ *d, size_t n, unsigned ৱর্ণ *md)
{
    স্থির unsigned ৱর্ণ m[SHA224_DIGEST_LENGTH];

    যদি (md == রিক্ত)
        md = m;
    ঘূৰাই EVP_Q_digest(রিক্ত, "SHA224", রিক্ত, d, n, md, রিক্ত) ? md : রিক্ত;
}

unsigned ৱর্ণ *SHA256(ধ্রুৱ unsigned ৱর্ণ *d, size_t n, unsigned ৱর্ণ *md)
{
    স্থির unsigned ৱর্ণ m[SHA256_DIGEST_LENGTH];

    যদি (md == রিক্ত)
        md = m;
    ঘূৰাই EVP_Q_digest(রিক্ত, "SHA256", রিক্ত, d, n, md, রিক্ত) ? md : রিক্ত;
}

unsigned ৱর্ণ *SHA384(ধ্রুৱ unsigned ৱর্ণ *d, size_t n, unsigned ৱর্ণ *md)
{
    স্থির unsigned ৱর্ণ m[SHA384_DIGEST_LENGTH];

    যদি (md == রিক্ত)
        md = m;
    ঘূৰাই EVP_Q_digest(রিক্ত, "SHA384", রিক্ত, d, n, md, রিক্ত) ? md : রিক্ত;
}

unsigned ৱর্ণ *SHA512(ধ্রুৱ unsigned ৱর্ণ *d, size_t n, unsigned ৱর্ণ *md)
{
    স্থির unsigned ৱর্ণ m[SHA512_DIGEST_LENGTH];

    যদি (md == রিক্ত)
        md = m;
    ঘূৰাই EVP_Q_digest(রিক্ত, "SHA512", রিক্ত, d, n, md, রিক্ত) ? md : রিক্ত;
}
