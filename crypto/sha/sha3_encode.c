/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* including crypto/sha.h requires this for SHA256_CTX */
#অন্তর্ভাৱ "internal/deprecated.h"

/*
 * NIST.SP.800-185 Encoding/Padding Methods used for SHA3 derived functions
 * e.g. It is used by KMAC and cSHAKE
 */

#অন্তর্ভাৱ <string.h> /* memcpy */
#অন্তর্ভাৱ <openssl/err.h>
#অন্তর্ভাৱ <openssl/proverr.h>
#অন্তর্ভাৱ "crypto/sha.h"
#অন্তর্ভাৱ "internal/common.h" /* ossl_assert */

/* Returns the number of bytes required to store 'bits' into a byte array */
স্থির unsigned পূর্ণাঙ্ক get_encode_size(size_t bits)
{
    unsigned পূর্ণাঙ্ক cnt = 0, sz = পরিমাণ(size_t);

    যেতিয়ালৈ (bits && (cnt < sz)) {
        ++cnt;
        bits >>= 8;
    }
    /* If bits is zero 1 byte is required */
    যদি (cnt == 0)
        cnt = 1;
    ঘূৰাই cnt;
}

/*
 * Convert an integer into bytes. The number of bytes is appended
 * to the end of the buffer.
 * Returns an array of bytes 'out' of size *out_len.
 *
 * e.g if bits = 32, out[2] = { 0x20, 0x01 }
 */
পূর্ণাঙ্ক ossl_sp800_185_ডান_encode(unsigned ৱর্ণ *out,
    size_t out_max_len, size_t *out_len,
    size_t bits)
{
    unsigned পূর্ণাঙ্ক len = get_encode_size(bits);
    পূর্ণাঙ্ক i;

    যদি (len >= out_max_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
        ঘূৰাই 0;
    }

    /* MSB's are at the start of the bytes array */
    বাবে (i = len - 1; i >= 0; --i) {
        out[i] = (unsigned ৱর্ণ)(bits & 0xFF);
        bits >>= 8;
    }
    /* Tack the length onto the end */
    out[len] = (unsigned ৱর্ণ)len;

    /* The Returned length includes the tacked on byte */
    *out_len = len + 1;
    ঘূৰাই 1;
}

/*
 * Encodes a string with a left encoded length added. Note that the
 * in_len is converted to bits (* 8).
 *
 * e.g- in="KMAC" gives out[6] = { 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43 }
 *                                 len   bits    K     M     A     C
 */
পূর্ণাঙ্ক ossl_sp800_185_encode_string(unsigned ৱর্ণ *out,
    size_t out_max_len, size_t *out_len,
    ধ্রুৱ unsigned ৱর্ণ *in, size_t in_len)
{
    যদি (in == রিক্ত) {
        *out_len = 0;
    } অন্যথা {
        size_t i, bits, len, sz;

        bits = 8 * in_len;
        len = get_encode_size(bits);
        sz = 1 + len + in_len;

        যদি (sz > out_max_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
            ঘূৰাই 0;
        }

        out[0] = (unsigned ৱর্ণ)len;
        বাবে (i = len; i > 0; --i) {
            out[i] = (bits & 0xFF);
            bits >>= 8;
        }
        memcpy(out + len + 1, in, in_len);
        *out_len = sz;
    }
    ঘূৰাই 1;
}

/*
 * Returns a zero padded encoding of the inputs in1 and an optional
 * in2 (can be NULL). The padded output must be a multiple of the blocksize 'w'.
 * The value of w is in bytes (< 256).
 *
 * The returned output is:
 *    zero_padded(multiple of w, (left_encode(w) || in1 [|| in2])
 */
পূর্ণাঙ্ক ossl_sp800_185_bytepad(unsigned ৱর্ণ *out, size_t out_len_max, size_t *out_len,
    ধ্রুৱ unsigned ৱর্ণ *in1, size_t in1_len,
    ধ্রুৱ unsigned ৱর্ণ *in2, size_t in2_len,
    size_t w)
{
    size_t len;
    unsigned ৱর্ণ *p = out;
    size_t sz;

    যদি (!ossl_assert(w <= 255))
        ঘূৰাই 0;
    sz = (2 + in1_len + (in2 != রিক্ত ? in2_len : 0) + w - 1) / w * w;
    যদি (out_len_max != 0 && sz > out_len_max)
        ঘূৰাই 0;

    যদি (out == রিক্ত) {
        যদি (out_len == রিক্ত) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            ঘূৰাই 0;
        }
        *out_len = sz;
        ঘূৰাই 1;
    }

    /* Left encoded w */
    *p++ = 1;
    *p++ = (unsigned ৱর্ণ)w;
    /* || in1 */
    memcpy(p, in1, in1_len);
    p += in1_len;
    /* [ || in2 ] */
    যদি (in2 != রিক্ত && in2_len > 0) {
        memcpy(p, in2, in2_len);
        p += in2_len;
    }
    /* Figure out the pad size (divisible by w) */
    len = p - out;
    /* zero pad the end of the buffer */
    যদি (sz != len)
        memset(p, 0, sz - len);
    যদি (out_len != রিক্ত)
        *out_len = sz;
    ঘূৰাই 1;
}
