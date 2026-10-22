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
#অন্তর্ভাব "internal/deprecated.h"

#অন্তর্ভাব <openssl/crypto.h>
#অন্তর্ভাব <openssl/opensslconf.h>

#অন্তর্ভাব <openssl/opensslv.h>
#অন্তর্ভাব <openssl/evp.h>
#অন্তর্ভাব <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#অন্তর্ভাব "sha_local.h"
#অন্তর্ভাব "crypto/sha.h"

পূর্ণসংখ্যা ossl_sha1_ctrl(SHA_CTX *sha1, পূর্ণসংখ্যা cmd, পূর্ণসংখ্যা mslen, শূন্য *ms)
{
    unsigned অক্ষর padtmp[40];
    unsigned অক্ষর sha1tmp[SHA_DIGEST_দৈর্ঘ্য];

    যদি (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        ফেরত -2;

    যদি (sha1 == ফাঁকা)
        ফেরত 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    যদি (mslen != 48)
        ফেরত 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    যদি (SHA1_Update(sha1, ms, mslen) <= 0)
        ফেরত 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, আকার(padtmp));

    যদি (!SHA1_Update(sha1, padtmp, আকার(padtmp)))
        ফেরত 0;

    যদি (!SHA1_Final(sha1tmp, sha1))
        ফেরত 0;

    /* Reinitialise context */

    যদি (!SHA1_Init(sha1))
        ফেরত 0;

    যদি (SHA1_Update(sha1, ms, mslen) <= 0)
        ফেরত 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, আকার(padtmp));

    যদি (!SHA1_Update(sha1, padtmp, আকার(padtmp)))
        ফেরত 0;

    যদি (!SHA1_Update(sha1, sha1tmp, আকার(sha1tmp)))
        ফেরত 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, আকার(sha1tmp));

    ফেরত 1;
}
