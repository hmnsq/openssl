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

정수 ossl_sha1_ctrl(SHA_CTX *sha1, 정수 cmd, 정수 mslen, void *ms)
{
    unsigned char padtmp[40];
    unsigned char sha1tmp[SHA_DIGEST_LENGTH];

    만약 (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        반환 -2;

    만약 (sha1 == NULL)
        반환 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    만약 (mslen != 48)
        반환 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    만약 (SHA1_Update(sha1, ms, mslen) <= 0)
        반환 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, sizeof(padtmp));

    만약 (!SHA1_Update(sha1, padtmp, sizeof(padtmp)))
        반환 0;

    만약 (!SHA1_Final(sha1tmp, sha1))
        반환 0;

    /* Reinitialise context */

    만약 (!SHA1_Init(sha1))
        반환 0;

    만약 (SHA1_Update(sha1, ms, mslen) <= 0)
        반환 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, sizeof(padtmp));

    만약 (!SHA1_Update(sha1, padtmp, sizeof(padtmp)))
        반환 0;

    만약 (!SHA1_Update(sha1, sha1tmp, sizeof(sha1tmp)))
        반환 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, sizeof(sha1tmp));

    반환 1;
}
