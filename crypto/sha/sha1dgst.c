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
#অন্তর্ভাৱ "internal/deprecated.h"

#অন্তর্ভাৱ <openssl/crypto.h>
#অন্তর্ভাৱ <openssl/opensslconf.h>

#অন্তর্ভাৱ <openssl/opensslv.h>
#অন্তর্ভাৱ <openssl/evp.h>
#অন্তর্ভাৱ <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#অন্তর্ভাৱ "sha_local.h"
#অন্তর্ভাৱ "crypto/sha.h"

পূর্ণাঙ্ক ossl_sha1_ctrl(SHA_CTX *sha1, পূর্ণাঙ্ক cmd, পূর্ণাঙ্ক mslen, শূন্য *ms)
{
    unsigned ৱর্ণ padtmp[40];
    unsigned ৱর্ণ sha1tmp[SHA_DIGEST_LENGTH];

    যদি (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        ঘূৰাই -2;

    যদি (sha1 == রিক্ত)
        ঘূৰাই 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    যদি (mslen != 48)
        ঘূৰাই 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    যদি (SHA1_Update(sha1, ms, mslen) <= 0)
        ঘূৰাই 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, পরিমাণ(padtmp));

    যদি (!SHA1_Update(sha1, padtmp, পরিমাণ(padtmp)))
        ঘূৰাই 0;

    যদি (!SHA1_Final(sha1tmp, sha1))
        ঘূৰাই 0;

    /* Reinitialise context */

    যদি (!SHA1_Init(sha1))
        ঘূৰাই 0;

    যদি (SHA1_Update(sha1, ms, mslen) <= 0)
        ঘূৰাই 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, পরিমাণ(padtmp));

    যদি (!SHA1_Update(sha1, padtmp, পরিমাণ(padtmp)))
        ঘূৰাই 0;

    যদি (!SHA1_Update(sha1, sha1tmp, পরিমাণ(sha1tmp)))
        ঘূৰাই 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, পরিমাণ(sha1tmp));

    ঘূৰাই 1;
}
