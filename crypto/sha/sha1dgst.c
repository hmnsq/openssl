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
#ಅನ್ತರ್ಭಾವ "internal/deprecated.h"

#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಅನ್ತರ್ಭಾವ <openssl/opensslconf.h>

#ಅನ್ತರ್ಭಾವ <openssl/opensslv.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#ಅನ್ತರ್ಭಾವ "sha_local.h"
#ಅನ್ತರ್ಭಾವ "crypto/sha.h"

ಪೂರ್ಣಾಂಕ ossl_sha1_ctrl(SHA_CTX *sha1, ಪೂರ್ಣಾಂಕ cmd, ಪೂರ್ಣಾಂಕ mslen, ಶೂನ್ಯ *ms)
{
    ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ padtmp[40];
    ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ sha1tmp[SHA_DIGEST_ಉದ್ದಳತೆ];

    ಆದರೆ (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        ಹಿಂತಿರುಗಿ -2;

    ಆದರೆ (sha1 == ಖಾಲಿ)
        ಹಿಂತಿರುಗಿ 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    ಆದರೆ (mslen != 48)
        ಹಿಂತಿರುಗಿ 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    ಆದರೆ (SHA1_Update(sha1, ms, mslen) <= 0)
        ಹಿಂತಿರುಗಿ 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, ಗಾತ್ರ(padtmp));

    ಆದರೆ (!SHA1_Update(sha1, padtmp, ಗಾತ್ರ(padtmp)))
        ಹಿಂತಿರುಗಿ 0;

    ಆದರೆ (!SHA1_Final(sha1tmp, sha1))
        ಹಿಂತಿರುಗಿ 0;

    /* Reinitialise context */

    ಆದರೆ (!SHA1_Init(sha1))
        ಹಿಂತಿರುಗಿ 0;

    ಆದರೆ (SHA1_Update(sha1, ms, mslen) <= 0)
        ಹಿಂತಿರುಗಿ 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, ಗಾತ್ರ(padtmp));

    ಆದರೆ (!SHA1_Update(sha1, padtmp, ಗಾತ್ರ(padtmp)))
        ಹಿಂತಿರುಗಿ 0;

    ಆದರೆ (!SHA1_Update(sha1, sha1tmp, ಗಾತ್ರ(sha1tmp)))
        ಹಿಂತಿರುಗಿ 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, ಗಾತ್ರ(sha1tmp));

    ಹಿಂತಿರುಗಿ 1;
}
