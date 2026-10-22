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
#अन्तर्भाव "internal/deprecated.h"

#अन्तर्भाव <openssl/crypto.h>
#अन्तर्भाव <openssl/opensslconf.h>

#अन्तर्भाव <openssl/opensslv.h>
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव <openssl/sha.h>

/* The implementation is in crypto/md32_common.inc */

#अन्तर्भाव "sha_local.h"
#अन्तर्भाव "crypto/sha.h"

पूर्णाङ्क ossl_sha1_ctrl(SHA_CTX *sha1, पूर्णाङ्क cmd, पूर्णाङ्क mslen, शून्य *ms)
{
    अचिह्नित वर्ण padtmp[40];
    अचिह्नित वर्ण sha1tmp[SHA_DIGEST_दीर्घता];

    यदि (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        प्रत्यागम -2;

    यदि (sha1 == रिक्त)
        प्रत्यागम 0;

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    यदि (mslen != 48)
        प्रत्यागम 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    यदि (SHA1_Update(sha1, ms, mslen) <= 0)
        प्रत्यागम 0;

    /* Set padtmp to pad_1 value */
    स्मृतिं_पूरय(padtmp, 0x36, परिमाण(padtmp));

    यदि (!SHA1_Update(sha1, padtmp, परिमाण(padtmp)))
        प्रत्यागम 0;

    यदि (!SHA1_Final(sha1tmp, sha1))
        प्रत्यागम 0;

    /* Reinitialise context */

    यदि (!SHA1_Init(sha1))
        प्रत्यागम 0;

    यदि (SHA1_Update(sha1, ms, mslen) <= 0)
        प्रत्यागम 0;

    /* Set padtmp to pad_2 value */
    स्मृतिं_पूरय(padtmp, 0x5c, परिमाण(padtmp));

    यदि (!SHA1_Update(sha1, padtmp, परिमाण(padtmp)))
        प्रत्यागम 0;

    यदि (!SHA1_Update(sha1, sha1tmp, परिमाण(sha1tmp)))
        प्रत्यागम 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    OPENSSL_cleanse(sha1tmp, परिमाण(sha1tmp));

    प्रत्यागम 1;
}
