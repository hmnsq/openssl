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
#અન્તર્ભાવ "internal/deprecated.h"

#અન્તર્ભાવ <openssl/crypto.h>
#અન્તર્ભાવ <openssl/opensslconf.h>

#અન્તર્ભાવ <openssl/opensslv.h>
#અન્તર્ભાવ <openssl/evp.h>
#અન્તર્ભાવ <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#અન્તર્ભાવ "sha_local.h"
#અન્તર્ભાવ "crypto/sha.h"

પૂર્ણાંક ossl_sha1_ctrl(SHA_CTX *sha1, પૂર્ણાંક cmd, પૂર્ણાંક mslen, શૂન્ય *ms)
{
    unsigned અક્ષર padtmp[40];
    unsigned અક્ષર sha1tmp[SHA_DIGEST_LENGTH];

    જો (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        પાછા -2;

    જો (sha1 == ખાલી)
        પાછા 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    જો (mslen != 48)
        પાછા 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    જો (SHA1_Update(sha1, ms, mslen) <= 0)
        પાછા 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, કદ(padtmp));

    જો (!SHA1_Update(sha1, padtmp, કદ(padtmp)))
        પાછા 0;

    જો (!SHA1_Final(sha1tmp, sha1))
        પાછા 0;

    /* Reinitialise context */

    જો (!SHA1_Init(sha1))
        પાછા 0;

    જો (SHA1_Update(sha1, ms, mslen) <= 0)
        પાછા 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, કદ(padtmp));

    જો (!SHA1_Update(sha1, padtmp, કદ(padtmp)))
        પાછા 0;

    જો (!SHA1_Update(sha1, sha1tmp, કદ(sha1tmp)))
        પાછા 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, કદ(sha1tmp));

    પાછા 1;
}
