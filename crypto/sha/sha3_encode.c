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
ساكن بیعلامت صحيح get_encode_اندازه(size_t بیتها)
{
    بیعلامت صحيح cnt = 0, sz = حجم(size_t);

    طالما (بیتها && (cnt < sz)) {
        ++cnt;
        بیتها >>= 8;
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
صحيح ossl_sp800_185_راست_encode(بیعلامت حرف *بیرون,
    size_t بیرون_max_len, size_t *بیرون_len,
    size_t بیتها)
{
    بیعلامت صحيح len = get_encode_اندازه(بیتها);
    صحيح i;

    إذا (len >= بیرون_max_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_درازی_TOO_LARGE);
        أرجع 0;
    }

    /* MSB's are at the start of the bytes array */
    لكل (i = len - 1; i >= 0; --i) {
        بیرون[i] = (بیعلامت حرف)(بیتها & 0xFF);
        بیتها >>= 8;
    }
    /* Tack the length onto the end */
    بیرون[len] = (بیعلامت حرف)len;

    /* The Returned length includes the tacked on byte */
    *بیرون_len = len + 1;
    أرجع 1;
}

/*
 * Encodes a string with a left encoded length added. Note that the
 * in_len is converted to bits (* 8).
 *
 * e.g- in="KMAC" gives out[6] = { 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43 }
 *                                 len   bits    K     M     A     C
 */
صحيح ossl_sp800_185_encode_string(بیعلامت حرف *بیرون,
    size_t بیرون_max_len, size_t *بیرون_len,
    ثابت بیعلامت حرف *درون, size_t درون_len)
{
    إذا (درون == عدم) {
        *بیرون_len = 0;
    } وإلا {
        size_t i, بیتها, len, sz;

        بیتها = 8 * درون_len;
        len = get_encode_اندازه(بیتها);
        sz = 1 + len + درون_len;

        إذا (sz > بیرون_max_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_درازی_TOO_LARGE);
            أرجع 0;
        }

        بیرون[0] = (بیعلامت حرف)len;
        لكل (i = len; i > 0; --i) {
            بیرون[i] = (بیتها & 0xFF);
            بیتها >>= 8;
        }
        کپی_حافظه(بیرون + len + 1, درون, درون_len);
        *بیرون_len = sz;
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
صحيح ossl_sp800_185_bytepad(بیعلامت حرف *بیرون, size_t بیرون_len_max, size_t *بیرون_len,
    ثابت بیعلامت حرف *in1, size_t in1_len,
    ثابت بیعلامت حرف *in2, size_t in2_len,
    size_t w)
{
    size_t len;
    بیعلامت حرف *p = بیرون;
    size_t sz;

    إذا (!ossl_assert(w <= 255))
        أرجع 0;
    sz = (2 + in1_len + (in2 != عدم ? in2_len : 0) + w - 1) / w * w;
    إذا (بیرون_len_max != 0 && sz > بیرون_len_max)
        أرجع 0;

    إذا (بیرون == عدم) {
        إذا (بیرون_len == عدم) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            أرجع 0;
        }
        *بیرون_len = sz;
        أرجع 1;
    }

    /* Left encoded w */
    *p++ = 1;
    *p++ = (بیعلامت حرف)w;
    /* || in1 */
    کپی_حافظه(p, in1, in1_len);
    p += in1_len;
    /* [ || in2 ] */
    إذا (in2 != عدم && in2_len > 0) {
        کپی_حافظه(p, in2, in2_len);
        p += in2_len;
    }
    /* Figure out the pad size (divisible by w) */
    len = p - بیرون;
    /* zero pad the end of the buffer */
    إذا (sz != len)
        memset(p, 0, sz - len);
    إذا (بیرون_len != عدم)
        *بیرون_len = sz;
    أرجع 1;
}
