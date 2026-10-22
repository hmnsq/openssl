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

ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ossl_sha1(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *d, size_t n, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *md)
{
    SHA_CTX c;
    ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ m[SHA_DIGEST_ಉದ್ದಳತೆ];

    ಆದರೆ (md == ಖಾಲಿ)
        md = m;
    ಆದರೆ (!SHA1_Init(&c))
        ಹಿಂತಿರುಗಿ ಖಾಲಿ;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, ಗಾತ್ರ(c));
    ಹಿಂತಿರುಗಿ md;
}

ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *SHA1(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *d, size_t n, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *md)
{
    ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ m[SHA_DIGEST_ಉದ್ದಳತೆ];

    ಆದರೆ (md == ಖಾಲಿ)
        md = m;
    ಹಿಂತಿರುಗಿ EVP_Q_digest(ಖಾಲಿ, "SHA1", ಖಾಲಿ, d, n, md, ಖಾಲಿ) ? md : ಖಾಲಿ;
}

ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *SHA224(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *d, size_t n, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *md)
{
    ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ m[SHA224_DIGEST_ಉದ್ದಳತೆ];

    ಆದರೆ (md == ಖಾಲಿ)
        md = m;
    ಹಿಂತಿರುಗಿ EVP_Q_digest(ಖಾಲಿ, "SHA224", ಖಾಲಿ, d, n, md, ಖಾಲಿ) ? md : ಖಾಲಿ;
}

ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *SHA256(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *d, size_t n, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *md)
{
    ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ m[SHA256_DIGEST_ಉದ್ದಳತೆ];

    ಆದರೆ (md == ಖಾಲಿ)
        md = m;
    ಹಿಂತಿರುಗಿ EVP_Q_digest(ಖಾಲಿ, "SHA256", ಖಾಲಿ, d, n, md, ಖಾಲಿ) ? md : ಖಾಲಿ;
}

ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *SHA384(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *d, size_t n, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *md)
{
    ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ m[SHA384_DIGEST_ಉದ್ದಳತೆ];

    ಆದರೆ (md == ಖಾಲಿ)
        md = m;
    ಹಿಂತಿರುಗಿ EVP_Q_digest(ಖಾಲಿ, "SHA384", ಖಾಲಿ, d, n, md, ಖಾಲಿ) ? md : ಖಾಲಿ;
}

ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *SHA512(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *d, size_t n, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *md)
{
    ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ m[SHA512_DIGEST_ಉದ್ದಳತೆ];

    ಆದರೆ (md == ಖಾಲಿ)
        md = m;
    ಹಿಂತಿರುಗಿ EVP_Q_digest(ಖಾಲಿ, "SHA512", ಖಾಲಿ, d, n, md, ಖಾಲಿ) ? md : ಖಾಲಿ;
}
