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
#ଅନ୍ତର୍ଭାଵ "internal/deprecated.h"

#ଅନ୍ତର୍ଭାଵ <openssl/crypto.h>
#ଅନ୍ତର୍ଭାଵ <openssl/opensslconf.h>

#ଅନ୍ତର୍ଭାଵ <openssl/opensslv.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#ଅନ୍ତର୍ଭାଵ <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#ଅନ୍ତର୍ଭାଵ "sha_local.h"
#ଅନ୍ତର୍ଭାଵ "crypto/sha.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା ossl_sha1_ctrl(SHA_CTX *sha1, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cmd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା mslen, ଶୂନ୍ୟ *ms)
{
    unsigned ଅକ୍ଷର padtmp[40];
    unsigned ଅକ୍ଷର sha1tmp[SHA_DIGEST_LENGTH];

    ଯଦି (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        ଫେରନ୍ତୁ -2;

    ଯଦି (sha1 == ଖାଲି)
        ଫେରନ୍ତୁ 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    ଯଦି (mslen != 48)
        ଫେରନ୍ତୁ 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    ଯଦି (SHA1_Update(sha1, ms, mslen) <= 0)
        ଫେରନ୍ତୁ 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, ଆକାର(padtmp));

    ଯଦି (!SHA1_Update(sha1, padtmp, ଆକାର(padtmp)))
        ଫେରନ୍ତୁ 0;

    ଯଦି (!SHA1_Final(sha1tmp, sha1))
        ଫେରନ୍ତୁ 0;

    /* Reinitialise context */

    ଯଦି (!SHA1_Init(sha1))
        ଫେରନ୍ତୁ 0;

    ଯଦି (SHA1_Update(sha1, ms, mslen) <= 0)
        ଫେରନ୍ତୁ 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, ଆକାର(padtmp));

    ଯଦି (!SHA1_Update(sha1, padtmp, ଆକାର(padtmp)))
        ଫେରନ୍ତୁ 0;

    ଯଦି (!SHA1_Update(sha1, sha1tmp, ଆକାର(sha1tmp)))
        ଫେରନ୍ତୁ 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, ଆକାର(sha1tmp));

    ଫେରନ୍ତୁ 1;
}
