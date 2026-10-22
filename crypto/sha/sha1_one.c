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
#ಅನ್ತರ್ಭಾವ "internal/deprecated.h"

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಅನ್ತರ್ಭಾವ <openssl/sha.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ "crypto/sha.h"

unsigned ವರ್ಣ *ossl_sha1(ಧ್ರುವ unsigned ವರ್ಣ *d, size_t n, unsigned ವರ್ಣ *md)
{
    SHA_CTX c;
    ಸ್ಥಿರ unsigned ವರ್ಣ m[SHA_DIGEST_LENGTH];

    ಯದಿ (md == ರಿಕ್ತ)
        md = m;
    ಯದಿ (!SHA1_Init(&c))
        ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, ಪರಿಮಾಣ(c));
    ಪ್ರತ್ಯಾಗಮ md;
}

unsigned ವರ್ಣ *SHA1(ಧ್ರುವ unsigned ವರ್ಣ *d, size_t n, unsigned ವರ್ಣ *md)
{
    ಸ್ಥಿರ unsigned ವರ್ಣ m[SHA_DIGEST_LENGTH];

    ಯದಿ (md == ರಿಕ್ತ)
        md = m;
    ಪ್ರತ್ಯಾಗಮ EVP_Q_digest(ರಿಕ್ತ, "SHA1", ರಿಕ್ತ, d, n, md, ರಿಕ್ತ) ? md : ರಿಕ್ತ;
}

unsigned ವರ್ಣ *SHA224(ಧ್ರುವ unsigned ವರ್ಣ *d, size_t n, unsigned ವರ್ಣ *md)
{
    ಸ್ಥಿರ unsigned ವರ್ಣ m[SHA224_DIGEST_LENGTH];

    ಯದಿ (md == ರಿಕ್ತ)
        md = m;
    ಪ್ರತ್ಯಾಗಮ EVP_Q_digest(ರಿಕ್ತ, "SHA224", ರಿಕ್ತ, d, n, md, ರಿಕ್ತ) ? md : ರಿಕ್ತ;
}

unsigned ವರ್ಣ *SHA256(ಧ್ರುವ unsigned ವರ್ಣ *d, size_t n, unsigned ವರ್ಣ *md)
{
    ಸ್ಥಿರ unsigned ವರ್ಣ m[SHA256_DIGEST_LENGTH];

    ಯದಿ (md == ರಿಕ್ತ)
        md = m;
    ಪ್ರತ್ಯಾಗಮ EVP_Q_digest(ರಿಕ್ತ, "SHA256", ರಿಕ್ತ, d, n, md, ರಿಕ್ತ) ? md : ರಿಕ್ತ;
}

unsigned ವರ್ಣ *SHA384(ಧ್ರುವ unsigned ವರ್ಣ *d, size_t n, unsigned ವರ್ಣ *md)
{
    ಸ್ಥಿರ unsigned ವರ್ಣ m[SHA384_DIGEST_LENGTH];

    ಯದಿ (md == ರಿಕ್ತ)
        md = m;
    ಪ್ರತ್ಯಾಗಮ EVP_Q_digest(ರಿಕ್ತ, "SHA384", ರಿಕ್ತ, d, n, md, ರಿಕ್ತ) ? md : ರಿಕ್ತ;
}

unsigned ವರ್ಣ *SHA512(ಧ್ರುವ unsigned ವರ್ಣ *d, size_t n, unsigned ವರ್ಣ *md)
{
    ಸ್ಥಿರ unsigned ವರ್ಣ m[SHA512_DIGEST_LENGTH];

    ಯದಿ (md == ರಿಕ್ತ)
        md = m;
    ಪ್ರತ್ಯಾಗಮ EVP_Q_digest(ರಿಕ್ತ, "SHA512", ರಿಕ್ತ, d, n, md, ರಿಕ್ತ) ? md : ರಿಕ್ತ;
}
