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

පූර්ණ_සංඛ්‍යා ossl_sha1_ctrl(SHA_CTX *sha1, පූර්ණ_සංඛ්‍යා cmd, පූර්ණ_සංඛ්‍යා mslen, void *ms)
{
    unsigned var_na padtmp[40];
    unsigned var_na sha1tmp[SHA_DIGEST_LENGTH];

    නම් (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        ආපසු -2;

    නම් (sha1 == NULL)
        ආපසු 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    නම් (mslen != 48)
        ආපසු 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    නම් (SHA1_Update(sha1, ms, mslen) <= 0)
        ආපසු 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, parimaa_na(padtmp));

    නම් (!SHA1_Update(sha1, padtmp, parimaa_na(padtmp)))
        ආපසු 0;

    නම් (!SHA1_Final(sha1tmp, sha1))
        ආපසු 0;

    /* Reinitialise context */

    නම් (!SHA1_Init(sha1))
        ආපසු 0;

    නම් (SHA1_Update(sha1, ms, mslen) <= 0)
        ආපසු 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, parimaa_na(padtmp));

    නම් (!SHA1_Update(sha1, padtmp, parimaa_na(padtmp)))
        ආපසු 0;

    නම් (!SHA1_Update(sha1, sha1tmp, parimaa_na(sha1tmp)))
        ආපසු 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, parimaa_na(sha1tmp));

    ආපසු 1;
}
