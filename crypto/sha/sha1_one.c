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
#ضمن "internal/deprecated.h"

#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <openssl/crypto.h>
#ضمن <openssl/sha.h>
#ضمن <openssl/evp.h>
#ضمن "crypto/sha.h"

بنانشانی حرف *ossl_sha1(ثابت بنانشانی حرف *d, size_t n, بنانشانی حرف *md)
{
    SHA_CTX c;
    ساكن بنانشانی حرف m[SHA_DIGEST_لمائی];

    إذا (md == عدم)
        md = m;
    إذا (!SHA1_Init(&c))
        أرجع عدم;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, حجم(c));
    أرجع md;
}

بنانشانی حرف *SHA1(ثابت بنانشانی حرف *d, size_t n, بنانشانی حرف *md)
{
    ساكن بنانشانی حرف m[SHA_DIGEST_لمائی];

    إذا (md == عدم)
        md = m;
    أرجع EVP_Q_digest(عدم, "SHA1", عدم, d, n, md, عدم) ? md : عدم;
}

بنانشانی حرف *SHA224(ثابت بنانشانی حرف *d, size_t n, بنانشانی حرف *md)
{
    ساكن بنانشانی حرف m[SHA224_DIGEST_لمائی];

    إذا (md == عدم)
        md = m;
    أرجع EVP_Q_digest(عدم, "SHA224", عدم, d, n, md, عدم) ? md : عدم;
}

بنانشانی حرف *SHA256(ثابت بنانشانی حرف *d, size_t n, بنانشانی حرف *md)
{
    ساكن بنانشانی حرف m[SHA256_DIGEST_لمائی];

    إذا (md == عدم)
        md = m;
    أرجع EVP_Q_digest(عدم, "SHA256", عدم, d, n, md, عدم) ? md : عدم;
}

بنانشانی حرف *SHA384(ثابت بنانشانی حرف *d, size_t n, بنانشانی حرف *md)
{
    ساكن بنانشانی حرف m[SHA384_DIGEST_لمائی];

    إذا (md == عدم)
        md = m;
    أرجع EVP_Q_digest(عدم, "SHA384", عدم, d, n, md, عدم) ? md : عدم;
}

بنانشانی حرف *SHA512(ثابت بنانشانی حرف *d, size_t n, بنانشانی حرف *md)
{
    ساكن بنانشانی حرف m[SHA512_DIGEST_لمائی];

    إذا (md == عدم)
        md = m;
    أرجع EVP_Q_digest(عدم, "SHA512", عدم, d, n, md, عدم) ? md : عدم;
}
