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
#ਅਨ੍ਤਰ੍ਭਾਵ "internal/deprecated.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/crypto.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/opensslconf.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/opensslv.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#ਅਨ੍ਤਰ੍ਭਾਵ "sha_local.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "crypto/sha.h"

ਪੂਰਨ ossl_sha1_ctrl(SHA_CTX *sha1, ਪੂਰਨ cmd, ਪੂਰਨ mslen, ਖਾਲੀ *ms)
{
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ padtmp[40];
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ sha1tmp[SHA_DIGEST_ਲੰਮਾਈ];

    ਜੇ (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        ਵਾਪਸ -2;

    ਜੇ (sha1 == ਨਿਰਾ)
        ਵਾਪਸ 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    ਜੇ (mslen != 48)
        ਵਾਪਸ 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    ਜੇ (SHA1_Update(sha1, ms, mslen) <= 0)
        ਵਾਪਸ 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, ਆਕਾਰ(padtmp));

    ਜੇ (!SHA1_Update(sha1, padtmp, ਆਕਾਰ(padtmp)))
        ਵਾਪਸ 0;

    ਜੇ (!SHA1_Final(sha1tmp, sha1))
        ਵਾਪਸ 0;

    /* Reinitialise context */

    ਜੇ (!SHA1_Init(sha1))
        ਵਾਪਸ 0;

    ਜੇ (SHA1_Update(sha1, ms, mslen) <= 0)
        ਵਾਪਸ 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, ਆਕਾਰ(padtmp));

    ਜੇ (!SHA1_Update(sha1, padtmp, ਆਕਾਰ(padtmp)))
        ਵਾਪਸ 0;

    ਜੇ (!SHA1_Update(sha1, sha1tmp, ਆਕਾਰ(sha1tmp)))
        ਵਾਪਸ 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, ਆਕਾਰ(sha1tmp));

    ਵਾਪਸ 1;
}
