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
#समावेश "internal/deprecated.h"

#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <openssl/crypto.h>
#समावेश <openssl/sha.h>
#समावेश <openssl/evp.h>
#समावेश "crypto/sha.h"

अचिन्हित अक्षर *ossl_sha1(स्थिर अचिन्हित अक्षर *d, माप_प्रकार n, अचिन्हित अक्षर *md)
{
    SHA_CTX c;
    अटल अचिन्हित अक्षर m[SHA_DIGEST_लंबाई];

    अगर (md == शून्य)
        md = m;
    अगर (!SHA1_Init(&c))
        वापस शून्य;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, माप(c));
    वापस md;
}

अचिन्हित अक्षर *SHA1(स्थिर अचिन्हित अक्षर *d, माप_प्रकार n, अचिन्हित अक्षर *md)
{
    अटल अचिन्हित अक्षर m[SHA_DIGEST_लंबाई];

    अगर (md == शून्य)
        md = m;
    वापस EVP_Q_digest(शून्य, "SHA1", शून्य, d, n, md, शून्य) ? md : शून्य;
}

अचिन्हित अक्षर *SHA224(स्थिर अचिन्हित अक्षर *d, माप_प्रकार n, अचिन्हित अक्षर *md)
{
    अटल अचिन्हित अक्षर m[SHA224_DIGEST_लंबाई];

    अगर (md == शून्य)
        md = m;
    वापस EVP_Q_digest(शून्य, "SHA224", शून्य, d, n, md, शून्य) ? md : शून्य;
}

अचिन्हित अक्षर *SHA256(स्थिर अचिन्हित अक्षर *d, माप_प्रकार n, अचिन्हित अक्षर *md)
{
    अटल अचिन्हित अक्षर m[SHA256_DIGEST_लंबाई];

    अगर (md == शून्य)
        md = m;
    वापस EVP_Q_digest(शून्य, "SHA256", शून्य, d, n, md, शून्य) ? md : शून्य;
}

अचिन्हित अक्षर *SHA384(स्थिर अचिन्हित अक्षर *d, माप_प्रकार n, अचिन्हित अक्षर *md)
{
    अटल अचिन्हित अक्षर m[SHA384_DIGEST_लंबाई];

    अगर (md == शून्य)
        md = m;
    वापस EVP_Q_digest(शून्य, "SHA384", शून्य, d, n, md, शून्य) ? md : शून्य;
}

अचिन्हित अक्षर *SHA512(स्थिर अचिन्हित अक्षर *d, माप_प्रकार n, अचिन्हित अक्षर *md)
{
    अटल अचिन्हित अक्षर m[SHA512_DIGEST_लंबाई];

    अगर (md == शून्य)
        md = m;
    वापस EVP_Q_digest(शून्य, "SHA512", शून्य, d, n, md, शून्य) ? md : शून्य;
}
