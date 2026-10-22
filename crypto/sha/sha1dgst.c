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
#شامل "internal/deprecated.h"

#شامل <openssl/crypto.h>
#شامل <openssl/opensslconf.h>

#شامل <openssl/opensslv.h>
#شامل <openssl/evp.h>
#شامل <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#شامل "sha_local.h"
#شامل "crypto/sha.h"

صحیح ossl_sha1_ctrl(SHA_CTX *sha1, صحیح cmd, صحیح mslen, تهی *ms)
{
    unsigned نویسه padtmp[40];
    unsigned نویسه sha1tmp[SHA_DIGEST_LENGTH];

    اگر (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        بازگشت -2;

    اگر (sha1 == پوچ)
        بازگشت 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    اگر (mslen != 48)
        بازگشت 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    اگر (SHA1_Update(sha1, ms, mslen) <= 0)
        بازگشت 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, اندازه(padtmp));

    اگر (!SHA1_Update(sha1, padtmp, اندازه(padtmp)))
        بازگشت 0;

    اگر (!SHA1_Final(sha1tmp, sha1))
        بازگشت 0;

    /* Reinitialise context */

    اگر (!SHA1_Init(sha1))
        بازگشت 0;

    اگر (SHA1_Update(sha1, ms, mslen) <= 0)
        بازگشت 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, اندازه(padtmp));

    اگر (!SHA1_Update(sha1, padtmp, اندازه(padtmp)))
        بازگشت 0;

    اگر (!SHA1_Update(sha1, sha1tmp, اندازه(sha1tmp)))
        بازگشت 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, اندازه(sha1tmp));

    بازگشت 1;
}
