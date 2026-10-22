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

غیرعلامتی حرف *ossl_sha1(ثابت غیرعلامتی حرف *d, size_t n, غیرعلامتی حرف *md)
{
    SHA_CTX c;
    ساکن غیرعلامتی حرف m[SHA_DIGEST_لمبائی];

    اگر (md == تہی)
        md = m;
    اگر (!SHA1_Init(&c))
        واپس تہی;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, حجم(c));
    واپس md;
}

غیرعلامتی حرف *SHA1(ثابت غیرعلامتی حرف *d, size_t n, غیرعلامتی حرف *md)
{
    ساکن غیرعلامتی حرف m[SHA_DIGEST_لمبائی];

    اگر (md == تہی)
        md = m;
    واپس EVP_Q_digest(تہی, "SHA1", تہی, d, n, md, تہی) ? md : تہی;
}

غیرعلامتی حرف *SHA224(ثابت غیرعلامتی حرف *d, size_t n, غیرعلامتی حرف *md)
{
    ساکن غیرعلامتی حرف m[SHA224_DIGEST_لمبائی];

    اگر (md == تہی)
        md = m;
    واپس EVP_Q_digest(تہی, "SHA224", تہی, d, n, md, تہی) ? md : تہی;
}

غیرعلامتی حرف *SHA256(ثابت غیرعلامتی حرف *d, size_t n, غیرعلامتی حرف *md)
{
    ساکن غیرعلامتی حرف m[SHA256_DIGEST_لمبائی];

    اگر (md == تہی)
        md = m;
    واپس EVP_Q_digest(تہی, "SHA256", تہی, d, n, md, تہی) ? md : تہی;
}

غیرعلامتی حرف *SHA384(ثابت غیرعلامتی حرف *d, size_t n, غیرعلامتی حرف *md)
{
    ساکن غیرعلامتی حرف m[SHA384_DIGEST_لمبائی];

    اگر (md == تہی)
        md = m;
    واپس EVP_Q_digest(تہی, "SHA384", تہی, d, n, md, تہی) ? md : تہی;
}

غیرعلامتی حرف *SHA512(ثابت غیرعلامتی حرف *d, size_t n, غیرعلامتی حرف *md)
{
    ساکن غیرعلامتی حرف m[SHA512_DIGEST_لمبائی];

    اگر (md == تہی)
        md = m;
    واپس EVP_Q_digest(تہی, "SHA512", تہی, d, n, md, تہی) ? md : تہی;
}
