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
#समावेश "internal/deprecated.h"

#समावेश <openssl/crypto.h>
#समावेश <openssl/opensslconf.h>

#समावेश <openssl/opensslv.h>
#समावेश <openssl/evp.h>
#समावेश <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#समावेश "sha_local.h"
#समावेश "crypto/sha.h"

पूर्णांक ossl_sha1_ctrl(SHA_CTX *sha1, पूर्णांक cmd, पूर्णांक mslen, व्योम *ms)
{
    अचिन्हित अक्षर padtmp[40];
    अचिन्हित अक्षर sha1tmp[SHA_DIGEST_लंबाई];

    अगर (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        वापस -2;

    अगर (sha1 == शून्य)
        वापस 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    अगर (mslen != 48)
        वापस 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    अगर (SHA1_Update(sha1, ms, mslen) <= 0)
        वापस 0;

    /* Set padtmp to pad_1 value */
    स_रखो(padtmp, 0x36, माप(padtmp));

    अगर (!SHA1_Update(sha1, padtmp, माप(padtmp)))
        वापस 0;

    अगर (!SHA1_Final(sha1tmp, sha1))
        वापस 0;

    /* Reinitialise context */

    अगर (!SHA1_Init(sha1))
        वापस 0;

    अगर (SHA1_Update(sha1, ms, mslen) <= 0)
        वापस 0;

    /* Set padtmp to pad_2 value */
    स_रखो(padtmp, 0x5c, माप(padtmp));

    अगर (!SHA1_Update(sha1, padtmp, माप(padtmp)))
        वापस 0;

    अगर (!SHA1_Update(sha1, sha1tmp, माप(sha1tmp)))
        वापस 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, माप(sha1tmp));

    वापस 1;
}
