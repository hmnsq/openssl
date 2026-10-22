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
#அந்தர்பாவ "internal/deprecated.h"

#அந்தர்பாவ <openssl/crypto.h>
#அந்தர்பாவ <openssl/opensslconf.h>

#அந்தர்பாவ <openssl/opensslv.h>
#அந்தர்பாவ <openssl/evp.h>
#அந்தர்பாவ <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#அந்தர்பாவ "sha_local.h"
#அந்தர்பாவ "crypto/sha.h"

முழு ossl_sha1_ctrl(SHA_CTX *sha1, முழு cmd, முழு mslen, வெறுமை *ms)
{
    unsigned எழுத்து padtmp[40];
    unsigned எழுத்து sha1tmp[SHA_DIGEST_LENGTH];

    எனில் (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        திரும்பு -2;

    எனில் (sha1 == வெற்று)
        திரும்பு 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    எனில் (mslen != 48)
        திரும்பு 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    எனில் (SHA1_Update(sha1, ms, mslen) <= 0)
        திரும்பு 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, அளவு(padtmp));

    எனில் (!SHA1_Update(sha1, padtmp, அளவு(padtmp)))
        திரும்பு 0;

    எனில் (!SHA1_Final(sha1tmp, sha1))
        திரும்பு 0;

    /* Reinitialise context */

    எனில் (!SHA1_Init(sha1))
        திரும்பு 0;

    எனில் (SHA1_Update(sha1, ms, mslen) <= 0)
        திரும்பு 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, அளவு(padtmp));

    எனில் (!SHA1_Update(sha1, padtmp, அளவு(padtmp)))
        திரும்பு 0;

    எனில் (!SHA1_Update(sha1, sha1tmp, அளவு(sha1tmp)))
        திரும்பு 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, அளவு(sha1tmp));

    திரும்பு 1;
}
