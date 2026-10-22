/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* including crypto/sha.h requires this for SHA256_CTX */
#شامل "internal/deprecated.h"

/*
 * NIST.SP.800-185 Encoding/Padding Methods used for SHA3 derived functions
 * e.g. It is used by KMAC and cSHAKE
 */

#شامل <string.h> /* memcpy */
#شامل <openssl/err.h>
#شامل <openssl/proverr.h>
#شامل "crypto/sha.h"
#شامل "internal/common.h" /* ossl_assert */

/* Returns the number of bytes required to store 'bits' into a byte array */
ساکن غیرعلامتی صحیح get_encode_سائز(size_t بٹ)
{
    غیرعلامتی صحیح cnt = 0, sz = حجم(size_t);

    جب (بٹ && (cnt < sz)) {
        ++cnt;
        بٹ >>= 8;
    }
    /* If bits is zero 1 byte is required */
    اگر (cnt == 0)
        cnt = 1;
    واپس cnt;
}

/*
 * Convert an integer into bytes. The number of bytes is appended
 * to the end of the buffer.
 * Returns an array of bytes 'out' of size *out_len.
 *
 * e.g if bits = 32, out[2] = { 0x20, 0x01 }
 */
صحیح ossl_sp800_185_دایاں_encode(غیرعلامتی حرف *برآمد,
    size_t برآمد_max_len, size_t *برآمد_len,
    size_t بٹ)
{
    غیرعلامتی صحیح len = get_encode_سائز(بٹ);
    صحیح i;

    اگر (len >= برآمد_max_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_لمبائی_TOO_LARGE);
        واپس 0;
    }

    /* MSB's are at the start of the bytes array */
    برائے (i = len - 1; i >= 0; --i) {
        برآمد[i] = (غیرعلامتی حرف)(بٹ & 0xFF);
        بٹ >>= 8;
    }
    /* Tack the length onto the end */
    برآمد[len] = (غیرعلامتی حرف)len;

    /* The Returned length includes the tacked on byte */
    *برآمد_len = len + 1;
    واپس 1;
}

/*
 * Encodes a string with a left encoded length added. Note that the
 * in_len is converted to bits (* 8).
 *
 * e.g- in="KMAC" gives out[6] = { 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43 }
 *                                 len   bits    K     M     A     C
 */
صحیح ossl_sp800_185_encode_string(غیرعلامتی حرف *برآمد,
    size_t برآمد_max_len, size_t *برآمد_len,
    ثابت غیرعلامتی حرف *اندر, size_t اندر_len)
{
    اگر (اندر == تہی) {
        *برآمد_len = 0;
    } ورنہ {
        size_t i, بٹ, len, sz;

        بٹ = 8 * اندر_len;
        len = get_encode_سائز(بٹ);
        sz = 1 + len + اندر_len;

        اگر (sz > برآمد_max_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_لمبائی_TOO_LARGE);
            واپس 0;
        }

        برآمد[0] = (غیرعلامتی حرف)len;
        برائے (i = len; i > 0; --i) {
            برآمد[i] = (بٹ & 0xFF);
            بٹ >>= 8;
        }
        حافظہ_نقل(برآمد + len + 1, اندر, اندر_len);
        *برآمد_len = sz;
    }
    واپس 1;
}

/*
 * Returns a zero padded encoding of the inputs in1 and an optional
 * in2 (can be NULL). The padded output must be a multiple of the blocksize 'w'.
 * The value of w is in bytes (< 256).
 *
 * The returned output is:
 *    zero_padded(multiple of w, (left_encode(w) || in1 [|| in2])
 */
صحیح ossl_sp800_185_bytepad(غیرعلامتی حرف *برآمد, size_t برآمد_len_max, size_t *برآمد_len,
    ثابت غیرعلامتی حرف *in1, size_t in1_len,
    ثابت غیرعلامتی حرف *in2, size_t in2_len,
    size_t w)
{
    size_t len;
    غیرعلامتی حرف *p = برآمد;
    size_t sz;

    اگر (!ossl_assert(w <= 255))
        واپس 0;
    sz = (2 + in1_len + (in2 != تہی ? in2_len : 0) + w - 1) / w * w;
    اگر (برآمد_len_max != 0 && sz > برآمد_len_max)
        واپس 0;

    اگر (برآمد == تہی) {
        اگر (برآمد_len == تہی) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            واپس 0;
        }
        *برآمد_len = sz;
        واپس 1;
    }

    /* Left encoded w */
    *p++ = 1;
    *p++ = (غیرعلامتی حرف)w;
    /* || in1 */
    حافظہ_نقل(p, in1, in1_len);
    p += in1_len;
    /* [ || in2 ] */
    اگر (in2 != تہی && in2_len > 0) {
        حافظہ_نقل(p, in2, in2_len);
        p += in2_len;
    }
    /* Figure out the pad size (divisible by w) */
    len = p - برآمد;
    /* zero pad the end of the buffer */
    اگر (sz != len)
        memset(p, 0, sz - len);
    اگر (برآمد_len != تہی)
        *برآمد_len = sz;
    واپس 1;
}
