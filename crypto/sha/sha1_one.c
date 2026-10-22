/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
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

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <openssl/crypto.h>
#అన్తర్భావ <openssl/sha.h>
#అన్తర్భావ <openssl/evp.h>
#అన్తర్భావ "crypto/sha.h"

గుర్తులేని అక్షరం *ossl_sha1(స్థిరరాశి గుర్తులేని అక్షరం *d, size_t n, గుర్తులేని అక్షరం *md)
{
    SHA_CTX c;
    స్థిర గుర్తులేని అక్షరం m[SHA_DIGEST_నిడివి];

    ఒకవేళ (md == ఖాళీ)
        md = m;
    ఒకవేళ (!SHA1_Init(&c))
        తిరిగి ఖాళీ;
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);
    OPENSSL_cleanse(&c, పరిమాణం(c));
    తిరిగి md;
}

గుర్తులేని అక్షరం *SHA1(స్థిరరాశి గుర్తులేని అక్షరం *d, size_t n, గుర్తులేని అక్షరం *md)
{
    స్థిర గుర్తులేని అక్షరం m[SHA_DIGEST_నిడివి];

    ఒకవేళ (md == ఖాళీ)
        md = m;
    తిరిగి EVP_Q_digest(ఖాళీ, "SHA1", ఖాళీ, d, n, md, ఖాళీ) ? md : ఖాళీ;
}

గుర్తులేని అక్షరం *SHA224(స్థిరరాశి గుర్తులేని అక్షరం *d, size_t n, గుర్తులేని అక్షరం *md)
{
    స్థిర గుర్తులేని అక్షరం m[SHA224_DIGEST_నిడివి];

    ఒకవేళ (md == ఖాళీ)
        md = m;
    తిరిగి EVP_Q_digest(ఖాళీ, "SHA224", ఖాళీ, d, n, md, ఖాళీ) ? md : ఖాళీ;
}

గుర్తులేని అక్షరం *SHA256(స్థిరరాశి గుర్తులేని అక్షరం *d, size_t n, గుర్తులేని అక్షరం *md)
{
    స్థిర గుర్తులేని అక్షరం m[SHA256_DIGEST_నిడివి];

    ఒకవేళ (md == ఖాళీ)
        md = m;
    తిరిగి EVP_Q_digest(ఖాళీ, "SHA256", ఖాళీ, d, n, md, ఖాళీ) ? md : ఖాళీ;
}

గుర్తులేని అక్షరం *SHA384(స్థిరరాశి గుర్తులేని అక్షరం *d, size_t n, గుర్తులేని అక్షరం *md)
{
    స్థిర గుర్తులేని అక్షరం m[SHA384_DIGEST_నిడివి];

    ఒకవేళ (md == ఖాళీ)
        md = m;
    తిరిగి EVP_Q_digest(ఖాళీ, "SHA384", ఖాళీ, d, n, md, ఖాళీ) ? md : ఖాళీ;
}

గుర్తులేని అక్షరం *SHA512(స్థిరరాశి గుర్తులేని అక్షరం *d, size_t n, గుర్తులేని అక్షరం *md)
{
    స్థిర గుర్తులేని అక్షరం m[SHA512_DIGEST_నిడివి];

    ఒకవేళ (md == ఖాళీ)
        md = m;
    తిరిగి EVP_Q_digest(ఖాళీ, "SHA512", ఖాళీ, d, n, md, ఖాళీ) ? md : ఖాళీ;
}
