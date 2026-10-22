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
#அந்தர்பாவ "internal/deprecated.h"

#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <openssl/crypto.h>
#அந்தர்பாவ <openssl/sha.h>
#அந்தர்பாவ <openssl/evp.h>
#அந்தர்பாவ "crypto/sha.h"

unsigned எழுத்து *ossl_sha1(மாறிலி unsigned எழுத்து *d, size_t n, unsigned எழுத்து *md)
{
    SHA_CTX c;
    நிலையான unsigned எழுத்து m[SHA_DIGEST_LENGTH];

    எனில் (md == வெற்று)
        md = m;
    எனில் (!SHA1_Init(&c))
        திரும்பு வெற்று;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, அளவு(c));
    திரும்பு md;
}

unsigned எழுத்து *SHA1(மாறிலி unsigned எழுத்து *d, size_t n, unsigned எழுத்து *md)
{
    நிலையான unsigned எழுத்து m[SHA_DIGEST_LENGTH];

    எனில் (md == வெற்று)
        md = m;
    திரும்பு EVP_Q_digest(வெற்று, "SHA1", வெற்று, d, n, md, வெற்று) ? md : வெற்று;
}

unsigned எழுத்து *SHA224(மாறிலி unsigned எழுத்து *d, size_t n, unsigned எழுத்து *md)
{
    நிலையான unsigned எழுத்து m[SHA224_DIGEST_LENGTH];

    எனில் (md == வெற்று)
        md = m;
    திரும்பு EVP_Q_digest(வெற்று, "SHA224", வெற்று, d, n, md, வெற்று) ? md : வெற்று;
}

unsigned எழுத்து *SHA256(மாறிலி unsigned எழுத்து *d, size_t n, unsigned எழுத்து *md)
{
    நிலையான unsigned எழுத்து m[SHA256_DIGEST_LENGTH];

    எனில் (md == வெற்று)
        md = m;
    திரும்பு EVP_Q_digest(வெற்று, "SHA256", வெற்று, d, n, md, வெற்று) ? md : வெற்று;
}

unsigned எழுத்து *SHA384(மாறிலி unsigned எழுத்து *d, size_t n, unsigned எழுத்து *md)
{
    நிலையான unsigned எழுத்து m[SHA384_DIGEST_LENGTH];

    எனில் (md == வெற்று)
        md = m;
    திரும்பு EVP_Q_digest(வெற்று, "SHA384", வெற்று, d, n, md, வெற்று) ? md : வெற்று;
}

unsigned எழுத்து *SHA512(மாறிலி unsigned எழுத்து *d, size_t n, unsigned எழுத்து *md)
{
    நிலையான unsigned எழுத்து m[SHA512_DIGEST_LENGTH];

    எனில் (md == வெற்று)
        md = m;
    திரும்பு EVP_Q_digest(வெற்று, "SHA512", வெற்று, d, n, md, வெற்று) ? md : வெற்று;
}
