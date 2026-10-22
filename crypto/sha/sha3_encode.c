/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* including crypto/sha.h requires this for SHA256_CTX */
#अन्तर्भाव "internal/deprecated.h"

/*
 * NIST.SP.800-185 Encoding/Padding Methods used for SHA3 derived functions
 * e.g. It is used by KMAC and cSHAKE
 */

#अन्तर्भाव <string.h> /* memcpy */
#अन्तर्भाव <openssl/err.h>
#अन्तर्भाव <openssl/proverr.h>
#अन्तर्भाव "crypto/sha.h"
#अन्तर्भाव "internal/common.h" /* ossl_assert */

/* Returns the number of bytes required to store 'bits' into a byte array */
स्थिर अचिह्नित पूर्णाङ्क get_encode_आकार(size_t द्वयङ्काः)
{
    अचिह्नित पूर्णाङ्क cnt = 0, sz = परिमाण(size_t);

    यावत् (द्वयङ्काः && (cnt < sz)) {
        ++cnt;
        द्वयङ्काः >>= 8;
    }
    /* If bits is zero 1 byte is required */
    यदि (cnt == 0)
        cnt = 1;
    प्रत्यागम cnt;
}

/*
 * Convert an integer into bytes. The number of bytes is appended
 * to the end of the buffer.
 * Returns an array of bytes 'out' of size *out_len.
 *
 * e.g if bits = 32, out[2] = { 0x20, 0x01 }
 */
पूर्णाङ्क ossl_sp800_185_दक्षिणः_encode(अचिह्नित वर्ण *बहिर्गमनम्,
    size_t बहिर्गमनम्_max_len, size_t *बहिर्गमनम्_len,
    size_t द्वयङ्काः)
{
    अचिह्नित पूर्णाङ्क len = get_encode_आकार(द्वयङ्काः);
    पूर्णाङ्क i;

    यदि (len >= बहिर्गमनम्_max_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_दीर्घता_TOO_LARGE);
        प्रत्यागम 0;
    }

    /* MSB's are at the start of the bytes array */
    प्रति (i = len - 1; i >= 0; --i) {
        बहिर्गमनम्[i] = (अचिह्नित वर्ण)(द्वयङ्काः & 0xFF);
        द्वयङ्काः >>= 8;
    }
    /* Tack the length onto the end */
    बहिर्गमनम्[len] = (अचिह्नित वर्ण)len;

    /* The Returned length includes the tacked on byte */
    *बहिर्गमनम्_len = len + 1;
    प्रत्यागम 1;
}

/*
 * Encodes a string with a left encoded length added. Note that the
 * in_len is converted to bits (* 8).
 *
 * e.g- in="KMAC" gives out[6] = { 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43 }
 *                                 len   bits    K     M     A     C
 */
पूर्णाङ्क ossl_sp800_185_encode_string(अचिह्नित वर्ण *बहिर्गमनम्,
    size_t बहिर्गमनम्_max_len, size_t *बहिर्गमनम्_len,
    ध्रुव अचिह्नित वर्ण *अन्तर्, size_t अन्तर्_len)
{
    यदि (अन्तर् == रिक्त) {
        *बहिर्गमनम्_len = 0;
    } अन्यथा {
        size_t i, द्वयङ्काः, len, sz;

        द्वयङ्काः = 8 * अन्तर्_len;
        len = get_encode_आकार(द्वयङ्काः);
        sz = 1 + len + अन्तर्_len;

        यदि (sz > बहिर्गमनम्_max_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_दीर्घता_TOO_LARGE);
            प्रत्यागम 0;
        }

        बहिर्गमनम्[0] = (अचिह्नित वर्ण)len;
        प्रति (i = len; i > 0; --i) {
            बहिर्गमनम्[i] = (द्वयङ्काः & 0xFF);
            द्वयङ्काः >>= 8;
        }
        स्मृतिं_प्रतिलिख(बहिर्गमनम् + len + 1, अन्तर्, अन्तर्_len);
        *बहिर्गमनम्_len = sz;
    }
    प्रत्यागम 1;
}

/*
 * Returns a zero padded encoding of the inputs in1 and an optional
 * in2 (can be NULL). The padded output must be a multiple of the blocksize 'w'.
 * The value of w is in bytes (< 256).
 *
 * The returned output is:
 *    zero_padded(multiple of w, (left_encode(w) || in1 [|| in2])
 */
पूर्णाङ्क ossl_sp800_185_bytepad(अचिह्नित वर्ण *बहिर्गमनम्, size_t बहिर्गमनम्_len_max, size_t *बहिर्गमनम्_len,
    ध्रुव अचिह्नित वर्ण *in1, size_t in1_len,
    ध्रुव अचिह्नित वर्ण *in2, size_t in2_len,
    size_t w)
{
    size_t len;
    अचिह्नित वर्ण *p = बहिर्गमनम्;
    size_t sz;

    यदि (!ossl_assert(w <= 255))
        प्रत्यागम 0;
    sz = (2 + in1_len + (in2 != रिक्त ? in2_len : 0) + w - 1) / w * w;
    यदि (बहिर्गमनम्_len_max != 0 && sz > बहिर्गमनम्_len_max)
        प्रत्यागम 0;

    यदि (बहिर्गमनम् == रिक्त) {
        यदि (बहिर्गमनम्_len == रिक्त) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            प्रत्यागम 0;
        }
        *बहिर्गमनम्_len = sz;
        प्रत्यागम 1;
    }

    /* Left encoded w */
    *p++ = 1;
    *p++ = (अचिह्नित वर्ण)w;
    /* || in1 */
    स्मृतिं_प्रतिलिख(p, in1, in1_len);
    p += in1_len;
    /* [ || in2 ] */
    यदि (in2 != रिक्त && in2_len > 0) {
        स्मृतिं_प्रतिलिख(p, in2, in2_len);
        p += in2_len;
    }
    /* Figure out the pad size (divisible by w) */
    len = p - बहिर्गमनम्;
    /* zero pad the end of the buffer */
    यदि (sz != len)
        स्मृतिं_पूरय(p, 0, sz - len);
    यदि (बहिर्गमनम्_len != रिक्त)
        *बहिर्गमनम्_len = sz;
    प्रत्यागम 1;
}
