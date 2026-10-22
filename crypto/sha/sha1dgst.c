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
#include "internal/deprecated.h"

#include <openssl/crypto.h>
#include <openssl/opensslconf.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#include "sha_local.h"
#include "crypto/sha.h"

puur_naa_nka ossl_sha1_ctrl(SHA_CTX *sha1, puur_naa_nka cmd, puur_naa_nka mslen, void *ms)
{
    unsigned var_na padtmp[40];
    unsigned var_na sha1tmp[SHA_DIGEST_LENGTH];

    ᯀᯮᯝ (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        ᯀᯮᯞ -2;

    ᯀᯮᯝ (sha1 == NULL)
        ᯀᯮᯞ 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    ᯀᯮᯝ (mslen != 48)
        ᯀᯮᯞ 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    ᯀᯮᯝ (SHA1_Update(sha1, ms, mslen) <= 0)
        ᯀᯮᯞ 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, parimaa_na(padtmp));

    ᯀᯮᯝ (!SHA1_Update(sha1, padtmp, parimaa_na(padtmp)))
        ᯀᯮᯞ 0;

    ᯀᯮᯝ (!SHA1_Final(sha1tmp, sha1))
        ᯀᯮᯞ 0;

    /* Reinitialise context */

    ᯀᯮᯝ (!SHA1_Init(sha1))
        ᯀᯮᯞ 0;

    ᯀᯮᯝ (SHA1_Update(sha1, ms, mslen) <= 0)
        ᯀᯮᯞ 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, parimaa_na(padtmp));

    ᯀᯮᯝ (!SHA1_Update(sha1, padtmp, parimaa_na(padtmp)))
        ᯀᯮᯞ 0;

    ᯀᯮᯝ (!SHA1_Update(sha1, sha1tmp, parimaa_na(sha1tmp)))
        ᯀᯮᯞ 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, parimaa_na(sha1tmp));

    ᯀᯮᯞ 1;
}
