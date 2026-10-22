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
#अन्तर्भाव "internal/deprecated.h"

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <openssl/crypto.h>
#अन्तर्भाव <openssl/sha.h>
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव "crypto/sha.h"

अचिन्हित अक्षर *ossl_sha1(स्थिरांक अचिन्हित अक्षर *d, माप_प्रकार n, अचिन्हित अक्षर *md)
{
    SHA_CTX c;
    स्थिर अचिन्हित अक्षर m[SHA_DIGEST_LENGTH];

    जर (md == रिक्त)
        md = m;
    जर (!SHA1_Init(&c))
        परत रिक्त;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, आकार(c));
    परत md;
}

अचिन्हित अक्षर *SHA1(स्थिरांक अचिन्हित अक्षर *d, माप_प्रकार n, अचिन्हित अक्षर *md)
{
    स्थिर अचिन्हित अक्षर m[SHA_DIGEST_LENGTH];

    जर (md == रिक्त)
        md = m;
    परत EVP_Q_digest(रिक्त, "SHA1", रिक्त, d, n, md, रिक्त) ? md : रिक्त;
}

अचिन्हित अक्षर *SHA224(स्थिरांक अचिन्हित अक्षर *d, माप_प्रकार n, अचिन्हित अक्षर *md)
{
    स्थिर अचिन्हित अक्षर m[SHA224_DIGEST_LENGTH];

    जर (md == रिक्त)
        md = m;
    परत EVP_Q_digest(रिक्त, "SHA224", रिक्त, d, n, md, रिक्त) ? md : रिक्त;
}

अचिन्हित अक्षर *SHA256(स्थिरांक अचिन्हित अक्षर *d, माप_प्रकार n, अचिन्हित अक्षर *md)
{
    स्थिर अचिन्हित अक्षर m[SHA256_DIGEST_LENGTH];

    जर (md == रिक्त)
        md = m;
    परत EVP_Q_digest(रिक्त, "SHA256", रिक्त, d, n, md, रिक्त) ? md : रिक्त;
}

अचिन्हित अक्षर *SHA384(स्थिरांक अचिन्हित अक्षर *d, माप_प्रकार n, अचिन्हित अक्षर *md)
{
    स्थिर अचिन्हित अक्षर m[SHA384_DIGEST_LENGTH];

    जर (md == रिक्त)
        md = m;
    परत EVP_Q_digest(रिक्त, "SHA384", रिक्त, d, n, md, रिक्त) ? md : रिक्त;
}

अचिन्हित अक्षर *SHA512(स्थिरांक अचिन्हित अक्षर *d, माप_प्रकार n, अचिन्हित अक्षर *md)
{
    स्थिर अचिन्हित अक्षर m[SHA512_DIGEST_LENGTH];

    जर (md == रिक्त)
        md = m;
    परत EVP_Q_digest(रिक्त, "SHA512", रिक्त, d, n, md, रिक्त) ? md : रिक्त;
}
