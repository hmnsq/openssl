/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* including crypto/sha.h requires this for SHA256_CTX */
#ਅਨ੍ਤਰ੍ਭਾਵ "internal/deprecated.h"

/*
 * NIST.SP.800-185 Encoding/Padding Methods used for SHA3 derived functions
 * e.g. It is used by KMAC and cSHAKE
 */

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h> /* memcpy */
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/err.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/proverr.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "crypto/sha.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "internal/common.h" /* ossl_assert */

/* Returns the number of bytes required to store 'bits' into a byte array */
ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ get_encode_ਮਾਪ(size_t ਬਿੱਟ)
{
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ cnt = 0, sz = ਆਕਾਰ(size_t);

    ਜਦੋਂ (ਬਿੱਟ && (cnt < sz)) {
        ++cnt;
        ਬਿੱਟ >>= 8;
    }
    /* If bits is zero 1 byte is required */
    ਜੇ (cnt == 0)
        cnt = 1;
    ਵਾਪਸ cnt;
}

/*
 * Convert an integer into bytes. The number of bytes is appended
 * to the end of the buffer.
 * Returns an array of bytes 'out' of size *out_len.
 *
 * e.g if bits = 32, out[2] = { 0x20, 0x01 }
 */
ਪੂਰਨ ossl_sp800_185_ਸੱਜਾ_encode(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ,
    size_t ਬਾਹਰਲਾ_max_len, size_t *ਬਾਹਰਲਾ_len,
    size_t ਬਿੱਟ)
{
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ len = get_encode_ਮਾਪ(ਬਿੱਟ);
    ਪੂਰਨ i;

    ਜੇ (len >= ਬਾਹਰਲਾ_max_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_ਲੰਮਾਈ_TOO_LARGE);
        ਵਾਪਸ 0;
    }

    /* MSB's are at the start of the bytes array */
    ਲਈ (i = len - 1; i >= 0; --i) {
        ਬਾਹਰਲਾ[i] = (ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)(ਬਿੱਟ & 0xFF);
        ਬਿੱਟ >>= 8;
    }
    /* Tack the length onto the end */
    ਬਾਹਰਲਾ[len] = (ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)len;

    /* The Returned length includes the tacked on byte */
    *ਬਾਹਰਲਾ_len = len + 1;
    ਵਾਪਸ 1;
}

/*
 * Encodes a string with a left encoded length added. Note that the
 * in_len is converted to bits (* 8).
 *
 * e.g- in="KMAC" gives out[6] = { 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43 }
 *                                 len   bits    K     M     A     C
 */
ਪੂਰਨ ossl_sp800_185_encode_string(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ,
    size_t ਬਾਹਰਲਾ_max_len, size_t *ਬਾਹਰਲਾ_len,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਵਿੱਚ, size_t ਵਿੱਚ_len)
{
    ਜੇ (ਵਿੱਚ == ਨਿਰਾ) {
        *ਬਾਹਰਲਾ_len = 0;
    } ਨਹੀਂਤਾਂ {
        size_t i, ਬਿੱਟ, len, sz;

        ਬਿੱਟ = 8 * ਵਿੱਚ_len;
        len = get_encode_ਮਾਪ(ਬਿੱਟ);
        sz = 1 + len + ਵਿੱਚ_len;

        ਜੇ (sz > ਬਾਹਰਲਾ_max_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_ਲੰਮਾਈ_TOO_LARGE);
            ਵਾਪਸ 0;
        }

        ਬਾਹਰਲਾ[0] = (ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)len;
        ਲਈ (i = len; i > 0; --i) {
            ਬਾਹਰਲਾ[i] = (ਬਿੱਟ & 0xFF);
            ਬਿੱਟ >>= 8;
        }
        ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਬਾਹਰਲਾ + len + 1, ਵਿੱਚ, ਵਿੱਚ_len);
        *ਬਾਹਰਲਾ_len = sz;
    }
    ਵਾਪਸ 1;
}

/*
 * Returns a zero padded encoding of the inputs in1 and an optional
 * in2 (can be NULL). The padded output must be a multiple of the blocksize 'w'.
 * The value of w is in bytes (< 256).
 *
 * The returned output is:
 *    zero_padded(multiple of w, (left_encode(w) || in1 [|| in2])
 */
ਪੂਰਨ ossl_sp800_185_bytepad(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ, size_t ਬਾਹਰਲਾ_len_max, size_t *ਬਾਹਰਲਾ_len,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *in1, size_t in1_len,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *in2, size_t in2_len,
    size_t w)
{
    size_t len;
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *p = ਬਾਹਰਲਾ;
    size_t sz;

    ਜੇ (!ossl_assert(w <= 255))
        ਵਾਪਸ 0;
    sz = (2 + in1_len + (in2 != ਨਿਰਾ ? in2_len : 0) + w - 1) / w * w;
    ਜੇ (ਬਾਹਰਲਾ_len_max != 0 && sz > ਬਾਹਰਲਾ_len_max)
        ਵਾਪਸ 0;

    ਜੇ (ਬਾਹਰਲਾ == ਨਿਰਾ) {
        ਜੇ (ਬਾਹਰਲਾ_len == ਨਿਰਾ) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            ਵਾਪਸ 0;
        }
        *ਬਾਹਰਲਾ_len = sz;
        ਵਾਪਸ 1;
    }

    /* Left encoded w */
    *p++ = 1;
    *p++ = (ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)w;
    /* || in1 */
    ਸਮ੍ਰਿਤੀ_ਨਕਲ(p, in1, in1_len);
    p += in1_len;
    /* [ || in2 ] */
    ਜੇ (in2 != ਨਿਰਾ && in2_len > 0) {
        ਸਮ੍ਰਿਤੀ_ਨਕਲ(p, in2, in2_len);
        p += in2_len;
    }
    /* Figure out the pad size (divisible by w) */
    len = p - ਬਾਹਰਲਾ;
    /* zero pad the end of the buffer */
    ਜੇ (sz != len)
        memset(p, 0, sz - len);
    ਜੇ (ਬਾਹਰਲਾ_len != ਨਿਰਾ)
        *ਬਾਹਰਲਾ_len = sz;
    ਵਾਪਸ 1;
}
