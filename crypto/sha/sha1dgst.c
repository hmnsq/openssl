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
#ضمن "internal/deprecated.h"

#ضمن <openssl/crypto.h>
#ضمن <openssl/opensslconf.h>

#ضمن <openssl/opensslv.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#ضمن "sha_local.h"
#ضمن "crypto/sha.h"

صحيح ossl_sha1_ctrl(SHA_CTX *sha1, صحيح cmd, صحيح mslen, فراغ *ms)
{
    unsigned حرف padtmp[40];
    unsigned حرف sha1tmp[SHA_DIGEST_LENGTH];

    ܐܢ (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        ܦܢܐ -2;

    ܐܢ (sha1 == عدم)
        ܦܢܐ 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    ܐܢ (mslen != 48)
        ܦܢܐ 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    ܐܢ (SHA1_Update(sha1, ms, mslen) <= 0)
        ܦܢܐ 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, حجم(padtmp));

    ܐܢ (!SHA1_Update(sha1, padtmp, حجم(padtmp)))
        ܦܢܐ 0;

    ܐܢ (!SHA1_Final(sha1tmp, sha1))
        ܦܢܐ 0;

    /* Reinitialise context */

    ܐܢ (!SHA1_Init(sha1))
        ܦܢܐ 0;

    ܐܢ (SHA1_Update(sha1, ms, mslen) <= 0)
        ܦܢܐ 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, حجم(padtmp));

    ܐܢ (!SHA1_Update(sha1, padtmp, حجم(padtmp)))
        ܦܢܐ 0;

    ܐܢ (!SHA1_Update(sha1, sha1tmp, حجم(sha1tmp)))
        ܦܢܐ 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, حجم(sha1tmp));

    ܦܢܐ 1;
}
