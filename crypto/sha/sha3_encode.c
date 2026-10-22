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
ساكن بنانشانی صحيح get_encode_ناپ(size_t بٹ)
{
    بنانشانی صحيح cnt = 0, sz = حجم(size_t);

    طالما (بٹ && (cnt < sz)) {
        ++cnt;
        بٹ >>= 8;
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
صحيح ossl_sp800_185_دایاں_encode(بنانشانی حرف *باہرلا,
    size_t باہرلا_max_len, size_t *باہرلا_len,
    size_t بٹ)
{
    بنانشانی صحيح len = get_encode_ناپ(بٹ);
    صحيح i;

    إذا (len >= باہرلا_max_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_لمائی_TOO_LARGE);
        أرجع 0;
    }

    /* MSB's are at the start of the bytes array */
    لكل (i = len - 1; i >= 0; --i) {
        باہرلا[i] = (بنانشانی حرف)(بٹ & 0xFF);
        بٹ >>= 8;
    }
    /* Tack the length onto the end */
    باہرلا[len] = (بنانشانی حرف)len;

    /* The Returned length includes the tacked on byte */
    *باہرلا_len = len + 1;
    أرجع 1;
}

/*
 * Encodes a string with a left encoded length added. Note that the
 * in_len is converted to bits (* 8).
 *
 * e.g- in="KMAC" gives out[6] = { 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43 }
 *                                 len   bits    K     M     A     C
 */
صحيح ossl_sp800_185_encode_string(بنانشانی حرف *باہرلا,
    size_t باہرلا_max_len, size_t *باہرلا_len,
    ثابت بنانشانی حرف *وچ, size_t وچ_len)
{
    إذا (وچ == عدم) {
        *باہرلا_len = 0;
    } وإلا {
        size_t i, بٹ, len, sz;

        بٹ = 8 * وچ_len;
        len = get_encode_ناپ(بٹ);
        sz = 1 + len + وچ_len;

        إذا (sz > باہرلا_max_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_لمائی_TOO_LARGE);
            أرجع 0;
        }

        باہرلا[0] = (بنانشانی حرف)len;
        لكل (i = len; i > 0; --i) {
            باہرلا[i] = (بٹ & 0xFF);
            بٹ >>= 8;
        }
        حافظہ_نقل(باہرلا + len + 1, وچ, وچ_len);
        *باہرلا_len = sz;
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
صحيح ossl_sp800_185_bytepad(بنانشانی حرف *باہرلا, size_t باہرلا_len_max, size_t *باہرلا_len,
    ثابت بنانشانی حرف *in1, size_t in1_len,
    ثابت بنانشانی حرف *in2, size_t in2_len,
    size_t w)
{
    size_t len;
    بنانشانی حرف *p = باہرلا;
    size_t sz;

    إذا (!ossl_assert(w <= 255))
        أرجع 0;
    sz = (2 + in1_len + (in2 != عدم ? in2_len : 0) + w - 1) / w * w;
    إذا (باہرلا_len_max != 0 && sz > باہرلا_len_max)
        أرجع 0;

    إذا (باہرلا == عدم) {
        إذا (باہرلا_len == عدم) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            أرجع 0;
        }
        *باہرلا_len = sz;
        أرجع 1;
    }

    /* Left encoded w */
    *p++ = 1;
    *p++ = (بنانشانی حرف)w;
    /* || in1 */
    حافظہ_نقل(p, in1, in1_len);
    p += in1_len;
    /* [ || in2 ] */
    إذا (in2 != عدم && in2_len > 0) {
        حافظہ_نقل(p, in2, in2_len);
        p += in2_len;
    }
    /* Figure out the pad size (divisible by w) */
    len = p - باہرلا;
    /* zero pad the end of the buffer */
    إذا (sz != len)
        memset(p, 0, sz - len);
    إذا (باہرلا_len != عدم)
        *باہرلا_len = sz;
    أرجع 1;
}
