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
#അന്തര്ഭാവ "internal/deprecated.h"

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <openssl/crypto.h>
#അന്തര്ഭാവ <openssl/sha.h>
#അന്തര്ഭാവ <openssl/evp.h>
#അന്തര്ഭാവ "crypto/sha.h"

unsigned അക്ഷരം *ossl_sha1(സ്ഥിരം unsigned അക്ഷരം *d, size_t n, unsigned അക്ഷരം *md)
{
    SHA_CTX c;
    സ്ഥിതം unsigned അക്ഷരം m[SHA_DIGEST_LENGTH];

    എങ്കിൽ (md == ശൂന്യ)
        md = m;
    എങ്കിൽ (!SHA1_Init(&c))
        തിരികെ ശൂന്യ;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, വലുപ്പം(c));
    തിരികെ md;
}

unsigned അക്ഷരം *SHA1(സ്ഥിരം unsigned അക്ഷരം *d, size_t n, unsigned അക്ഷരം *md)
{
    സ്ഥിതം unsigned അക്ഷരം m[SHA_DIGEST_LENGTH];

    എങ്കിൽ (md == ശൂന്യ)
        md = m;
    തിരികെ EVP_Q_digest(ശൂന്യ, "SHA1", ശൂന്യ, d, n, md, ശൂന്യ) ? md : ശൂന്യ;
}

unsigned അക്ഷരം *SHA224(സ്ഥിരം unsigned അക്ഷരം *d, size_t n, unsigned അക്ഷരം *md)
{
    സ്ഥിതം unsigned അക്ഷരം m[SHA224_DIGEST_LENGTH];

    എങ്കിൽ (md == ശൂന്യ)
        md = m;
    തിരികെ EVP_Q_digest(ശൂന്യ, "SHA224", ശൂന്യ, d, n, md, ശൂന്യ) ? md : ശൂന്യ;
}

unsigned അക്ഷരം *SHA256(സ്ഥിരം unsigned അക്ഷരം *d, size_t n, unsigned അക്ഷരം *md)
{
    സ്ഥിതം unsigned അക്ഷരം m[SHA256_DIGEST_LENGTH];

    എങ്കിൽ (md == ശൂന്യ)
        md = m;
    തിരികെ EVP_Q_digest(ശൂന്യ, "SHA256", ശൂന്യ, d, n, md, ശൂന്യ) ? md : ശൂന്യ;
}

unsigned അക്ഷരം *SHA384(സ്ഥിരം unsigned അക്ഷരം *d, size_t n, unsigned അക്ഷരം *md)
{
    സ്ഥിതം unsigned അക്ഷരം m[SHA384_DIGEST_LENGTH];

    എങ്കിൽ (md == ശൂന്യ)
        md = m;
    തിരികെ EVP_Q_digest(ശൂന്യ, "SHA384", ശൂന്യ, d, n, md, ശൂന്യ) ? md : ശൂന്യ;
}

unsigned അക്ഷരം *SHA512(സ്ഥിരം unsigned അക്ഷരം *d, size_t n, unsigned അക്ഷരം *md)
{
    സ്ഥിതം unsigned അക്ഷരം m[SHA512_DIGEST_LENGTH];

    എങ്കിൽ (md == ശൂന്യ)
        md = m;
    തിരികെ EVP_Q_digest(ശൂന്യ, "SHA512", ശൂന്യ, d, n, md, ശൂന്യ) ? md : ശൂന്യ;
}
