/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* including crypto/sha.h requires this for SHA256_CTX */
#ضمن "internal/deprecated.h"

/*
 * NIST.SP.800-185 Encoding/Padding Methods used for SHA3 derived functions
 * e.g. It is used by KMAC and cSHAKE
 */

#ضمن <string.h> /* memcpy */
#ضمن <openssl/err.h>
#ضمن <openssl/proverr.h>
#ضمن "crypto/sha.h"
#ضمن "internal/common.h" /* ossl_assert */

/* Returns the number of bytes required to store 'bits' into a byte array */
ساكن unsigned صحيح get_encode_size(size_t bits)
{
    unsigned صحيح cnt = 0, sz = حجم(size_t);

    طالما (bits && (cnt < sz)) {
        ++cnt;
        bits >>= 8;
    }
    /* If bits is zero 1 byte is required */
    إذا (cnt == 0)
        cnt = 1;
    أرجع cnt;
}

/*
 * Convert an integer into bytes. The number of bytes is appended
 * to the end of the buffer.
 * Returns an array of bytes 'out' of size *out_len.
 *
 * e.g if bits = 32, out[2] = { 0x20, 0x01 }
 */
صحيح ossl_sp800_185_ئوڭ_encode(unsigned حرف *out,
    size_t out_max_len, size_t *out_len,
    size_t bits)
{
    unsigned صحيح len = get_encode_size(bits);
    صحيح i;

    إذا (len >= out_max_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
        أرجع 0;
    }

    /* MSB's are at the start of the bytes array */
    لكل (i = len - 1; i >= 0; --i) {
        out[i] = (unsigned حرف)(bits & 0xFF);
        bits >>= 8;
    }
    /* Tack the length onto the end */
    out[len] = (unsigned حرف)len;

    /* The Returned length includes the tacked on byte */
    *out_len = len + 1;
    أرجع 1;
}

/*
 * Encodes a string with a left encoded length added. Note that the
 * in_len is converted to bits (* 8).
 *
 * e.g- in="KMAC" gives out[6] = { 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43 }
 *                                 len   bits    K     M     A     C
 */
صحيح ossl_sp800_185_encode_string(unsigned حرف *out,
    size_t out_max_len, size_t *out_len,
    ثابت unsigned حرف *in, size_t in_len)
{
    إذا (in == عدم) {
        *out_len = 0;
    } وإلا {
        size_t i, bits, len, sz;

        bits = 8 * in_len;
        len = get_encode_size(bits);
        sz = 1 + len + in_len;

        إذا (sz > out_max_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
            أرجع 0;
        }

        out[0] = (unsigned حرف)len;
        لكل (i = len; i > 0; --i) {
            out[i] = (bits & 0xFF);
            bits >>= 8;
        }
        memcpy(out + len + 1, in, in_len);
        *out_len = sz;
    }
    أرجع 1;
}

/*
 * Returns a zero padded encoding of the inputs in1 and an optional
 * in2 (can be NULL). The padded output must be a multiple of the blocksize 'w'.
 * The value of w is in bytes (< 256).
 *
 * The returned output is:
 *    zero_padded(multiple of w, (left_encode(w) || in1 [|| in2])
 */
صحيح ossl_sp800_185_bytepad(unsigned حرف *out, size_t out_len_max, size_t *out_len,
    ثابت unsigned حرف *in1, size_t in1_len,
    ثابت unsigned حرف *in2, size_t in2_len,
    size_t w)
{
    size_t len;
    unsigned حرف *p = out;
    size_t sz;

    إذا (!ossl_assert(w <= 255))
        أرجع 0;
    sz = (2 + in1_len + (in2 != عدم ? in2_len : 0) + w - 1) / w * w;
    إذا (out_len_max != 0 && sz > out_len_max)
        أرجع 0;

    إذا (out == عدم) {
        إذا (out_len == عدم) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            أرجع 0;
        }
        *out_len = sz;
        أرجع 1;
    }

    /* Left encoded w */
    *p++ = 1;
    *p++ = (unsigned حرف)w;
    /* || in1 */
    memcpy(p, in1, in1_len);
    p += in1_len;
    /* [ || in2 ] */
    إذا (in2 != عدم && in2_len > 0) {
        memcpy(p, in2, in2_len);
        p += in2_len;
    }
    /* Figure out the pad size (divisible by w) */
    len = p - out;
    /* zero pad the end of the buffer */
    إذا (sz != len)
        memset(p, 0, sz - len);
    إذا (out_len != عدم)
        *out_len = sz;
    أرجع 1;
}
