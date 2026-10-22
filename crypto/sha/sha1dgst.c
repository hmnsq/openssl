/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
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

#അന്തര്ഭാവ <openssl/crypto.h>
#അന്തര്ഭാവ <openssl/opensslconf.h>

#അന്തര്ഭാവ <openssl/opensslv.h>
#അന്തര്ഭാവ <openssl/evp.h>
#അന്തര്ഭാവ <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#അന്തര്ഭാവ "sha_local.h"
#അന്തര്ഭാവ "crypto/sha.h"

പൂർണ്ണസംഖ്യ ossl_sha1_ctrl(SHA_CTX *sha1, പൂർണ്ണസംഖ്യ cmd, പൂർണ്ണസംഖ്യ mslen, ശൂന്യം *ms)
{
    unsigned അക്ഷരം padtmp[40];
    unsigned അക്ഷരം sha1tmp[SHA_DIGEST_LENGTH];

    എങ്കിൽ (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        തിരികെ -2;

    എങ്കിൽ (sha1 == ശൂന്യ)
        തിരികെ 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    എങ്കിൽ (mslen != 48)
        തിരികെ 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    എങ്കിൽ (SHA1_Update(sha1, ms, mslen) <= 0)
        തിരികെ 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, വലുപ്പം(padtmp));

    എങ്കിൽ (!SHA1_Update(sha1, padtmp, വലുപ്പം(padtmp)))
        തിരികെ 0;

    എങ്കിൽ (!SHA1_Final(sha1tmp, sha1))
        തിരികെ 0;

    /* Reinitialise context */

    എങ്കിൽ (!SHA1_Init(sha1))
        തിരികെ 0;

    എങ്കിൽ (SHA1_Update(sha1, ms, mslen) <= 0)
        തിരികെ 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, വലുപ്പം(padtmp));

    എങ്കിൽ (!SHA1_Update(sha1, padtmp, വലുപ്പം(padtmp)))
        തിരികെ 0;

    എങ്കിൽ (!SHA1_Update(sha1, sha1tmp, വലുപ്പം(sha1tmp)))
        തിരികെ 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, വലുപ്പം(sha1tmp));

    തിരികെ 1;
}
