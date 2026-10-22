/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* including crypto/sha.h requires this for SHA256_CTX */
#అన్తర్భావ "internal/deprecated.h"

/*
 * NIST.SP.800-185 Encoding/Padding Methods used for SHA3 derived functions
 * e.g. It is used by KMAC and cSHAKE
 */

#అన్తర్భావ <string.h> /* memcpy */
#అన్తర్భావ <openssl/err.h>
#అన్తర్భావ <openssl/proverr.h>
#అన్తర్భావ "crypto/sha.h"
#అన్తర్భావ "internal/common.h" /* ossl_assert */

/* Returns the number of bytes required to store 'bits' into a byte array */
స్థిర గుర్తులేని పూర్ణాంకం get_encode_కొలత(size_t బిట్లు)
{
    గుర్తులేని పూర్ణాంకం cnt = 0, sz = పరిమాణం(size_t);

    అయితే (బిట్లు && (cnt < sz)) {
        ++cnt;
        బిట్లు >>= 8;
    }
    /* If bits is zero 1 byte is required */
    ఒకవేళ (cnt == 0)
        cnt = 1;
    తిరిగి cnt;
}

/*
 * Convert an integer into bytes. The number of bytes is appended
 * to the end of the buffer.
 * Returns an array of bytes 'out' of size *out_len.
 *
 * e.g if bits = 32, out[2] = { 0x20, 0x01 }
 */
పూర్ణాంకం ossl_sp800_185_కుడి_encode(గుర్తులేని అక్షరం *బహిర్గతం,
    size_t బహిర్గతం_max_len, size_t *బహిర్గతం_len,
    size_t బిట్లు)
{
    గుర్తులేని పూర్ణాంకం len = get_encode_కొలత(బిట్లు);
    పూర్ణాంకం i;

    ఒకవేళ (len >= బహిర్గతం_max_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_నిడివి_TOO_LARGE);
        తిరిగి 0;
    }

    /* MSB's are at the start of the bytes array */
    కొరకు (i = len - 1; i >= 0; --i) {
        బహిర్గతం[i] = (గుర్తులేని అక్షరం)(బిట్లు & 0xFF);
        బిట్లు >>= 8;
    }
    /* Tack the length onto the end */
    బహిర్గతం[len] = (గుర్తులేని అక్షరం)len;

    /* The Returned length includes the tacked on byte */
    *బహిర్గతం_len = len + 1;
    తిరిగి 1;
}

/*
 * Encodes a string with a left encoded length added. Note that the
 * in_len is converted to bits (* 8).
 *
 * e.g- in="KMAC" gives out[6] = { 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43 }
 *                                 len   bits    K     M     A     C
 */
పూర్ణాంకం ossl_sp800_185_encode_string(గుర్తులేని అక్షరం *బహిర్గతం,
    size_t బహిర్గతం_max_len, size_t *బహిర్గతం_len,
    స్థిరరాశి గుర్తులేని అక్షరం *లోపల, size_t లోపల_len)
{
    ఒకవేళ (లోపల == ఖాళీ) {
        *బహిర్గతం_len = 0;
    } లేకపోతే {
        size_t i, బిట్లు, len, sz;

        బిట్లు = 8 * లోపల_len;
        len = get_encode_కొలత(బిట్లు);
        sz = 1 + len + లోపల_len;

        ఒకవేళ (sz > బహిర్గతం_max_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_నిడివి_TOO_LARGE);
            తిరిగి 0;
        }

        బహిర్గతం[0] = (గుర్తులేని అక్షరం)len;
        కొరకు (i = len; i > 0; --i) {
            బహిర్గతం[i] = (బిట్లు & 0xFF);
            బిట్లు >>= 8;
        }
        జ్ఞాపకం_నకలు(బహిర్గతం + len + 1, లోపల, లోపల_len);
        *బహిర్గతం_len = sz;
    }
    తిరిగి 1;
}

/*
 * Returns a zero padded encoding of the inputs in1 and an optional
 * in2 (can be NULL). The padded output must be a multiple of the blocksize 'w'.
 * The value of w is in bytes (< 256).
 *
 * The returned output is:
 *    zero_padded(multiple of w, (left_encode(w) || in1 [|| in2])
 */
పూర్ణాంకం ossl_sp800_185_bytepad(గుర్తులేని అక్షరం *బహిర్గతం, size_t బహిర్గతం_len_max, size_t *బహిర్గతం_len,
    స్థిరరాశి గుర్తులేని అక్షరం *in1, size_t in1_len,
    స్థిరరాశి గుర్తులేని అక్షరం *in2, size_t in2_len,
    size_t w)
{
    size_t len;
    గుర్తులేని అక్షరం *p = బహిర్గతం;
    size_t sz;

    ఒకవేళ (!ossl_assert(w <= 255))
        తిరిగి 0;
    sz = (2 + in1_len + (in2 != ఖాళీ ? in2_len : 0) + w - 1) / w * w;
    ఒకవేళ (బహిర్గతం_len_max != 0 && sz > బహిర్గతం_len_max)
        తిరిగి 0;

    ఒకవేళ (బహిర్గతం == ఖాళీ) {
        ఒకవేళ (బహిర్గతం_len == ఖాళీ) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            తిరిగి 0;
        }
        *బహిర్గతం_len = sz;
        తిరిగి 1;
    }

    /* Left encoded w */
    *p++ = 1;
    *p++ = (గుర్తులేని అక్షరం)w;
    /* || in1 */
    జ్ఞాపకం_నకలు(p, in1, in1_len);
    p += in1_len;
    /* [ || in2 ] */
    ఒకవేళ (in2 != ఖాళీ && in2_len > 0) {
        జ్ఞాపకం_నకలు(p, in2, in2_len);
        p += in2_len;
    }
    /* Figure out the pad size (divisible by w) */
    len = p - బహిర్గతం;
    /* zero pad the end of the buffer */
    ఒకవేళ (sz != len)
        memset(p, 0, sz - len);
    ఒకవేళ (బహిర్గతం_len != ఖాళీ)
        *బహిర్గతం_len = sz;
    తిరిగి 1;
}
