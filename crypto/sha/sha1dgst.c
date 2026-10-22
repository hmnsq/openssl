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
#అన్తర్భావ "internal/deprecated.h"

#అన్తర్భావ <openssl/crypto.h>
#అన్తర్భావ <openssl/opensslconf.h>

#అన్తర్భావ <openssl/opensslv.h>
#అన్తర్భావ <openssl/evp.h>
#అన్తర్భావ <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#అన్తర్భావ "sha_local.h"
#అన్తర్భావ "crypto/sha.h"

పూర్ణాంకం ossl_sha1_ctrl(SHA_CTX *sha1, పూర్ణాంకం cmd, పూర్ణాంకం mslen, శూన్య *ms)
{
    గుర్తులేని అక్షరం padtmp[40];
    గుర్తులేని అక్షరం sha1tmp[SHA_DIGEST_నిడివి];

    ఒకవేళ (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        తిరిగి -2;

    ఒకవేళ (sha1 == ఖాళీ)
        తిరిగి 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    ఒకవేళ (mslen != 48)
        తిరిగి 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    ఒకవేళ (SHA1_Update(sha1, ms, mslen) <= 0)
        తిరిగి 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, పరిమాణం(padtmp));

    ఒకవేళ (!SHA1_Update(sha1, padtmp, పరిమాణం(padtmp)))
        తిరిగి 0;

    ఒకవేళ (!SHA1_Final(sha1tmp, sha1))
        తిరిగి 0;

    /* Reinitialise context */

    ఒకవేళ (!SHA1_Init(sha1))
        తిరిగి 0;

    ఒకవేళ (SHA1_Update(sha1, ms, mslen) <= 0)
        తిరిగి 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, పరిమాణం(padtmp));

    ఒకవేళ (!SHA1_Update(sha1, padtmp, పరిమాణం(padtmp)))
        తిరిగి 0;

    ఒకవేళ (!SHA1_Update(sha1, sha1tmp, పరిమాణం(sha1tmp)))
        తిరిగి 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, పరిమాణం(sha1tmp));

    తిరిగి 1;
}
