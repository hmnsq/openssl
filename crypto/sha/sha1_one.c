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

unsigned वर्ण *ossl_sha1(ध्रुव unsigned वर्ण *d, size_t n, unsigned वर्ण *md)
{
    SHA_CTX c;
    स्थिर unsigned वर्ण m[SHA_DIGEST_LENGTH];

    जइ (md == रिक्त)
        md = m;
    जइ (!SHA1_Init(&c))
        प्रत्यागम रिक्त;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, परिमाण(c));
    प्रत्यागम md;
}

unsigned वर्ण *SHA1(ध्रुव unsigned वर्ण *d, size_t n, unsigned वर्ण *md)
{
    स्थिर unsigned वर्ण m[SHA_DIGEST_LENGTH];

    जइ (md == रिक्त)
        md = m;
    प्रत्यागम EVP_Q_digest(रिक्त, "SHA1", रिक्त, d, n, md, रिक्त) ? md : रिक्त;
}

unsigned वर्ण *SHA224(ध्रुव unsigned वर्ण *d, size_t n, unsigned वर्ण *md)
{
    स्थिर unsigned वर्ण m[SHA224_DIGEST_LENGTH];

    जइ (md == रिक्त)
        md = m;
    प्रत्यागम EVP_Q_digest(रिक्त, "SHA224", रिक्त, d, n, md, रिक्त) ? md : रिक्त;
}

unsigned वर्ण *SHA256(ध्रुव unsigned वर्ण *d, size_t n, unsigned वर्ण *md)
{
    स्थिर unsigned वर्ण m[SHA256_DIGEST_LENGTH];

    जइ (md == रिक्त)
        md = m;
    प्रत्यागम EVP_Q_digest(रिक्त, "SHA256", रिक्त, d, n, md, रिक्त) ? md : रिक्त;
}

unsigned वर्ण *SHA384(ध्रुव unsigned वर्ण *d, size_t n, unsigned वर्ण *md)
{
    स्थिर unsigned वर्ण m[SHA384_DIGEST_LENGTH];

    जइ (md == रिक्त)
        md = m;
    प्रत्यागम EVP_Q_digest(रिक्त, "SHA384", रिक्त, d, n, md, रिक्त) ? md : रिक्त;
}

unsigned वर्ण *SHA512(ध्रुव unsigned वर्ण *d, size_t n, unsigned वर्ण *md)
{
    स्थिर unsigned वर्ण m[SHA512_DIGEST_LENGTH];

    जइ (md == रिक्त)
        md = m;
    प्रत्यागम EVP_Q_digest(रिक्त, "SHA512", रिक्त, d, n, md, रिक्त) ? md : रिक्त;
}
