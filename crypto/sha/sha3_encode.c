/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* including crypto/sha.h requires this for SHA256_CTX */
#ಅನ್ತರ್ಭಾವ "internal/deprecated.h"

/*
 * NIST.SP.800-185 Encoding/Padding Methods used for SHA3 derived functions
 * e.g. It is used by KMAC and cSHAKE
 */

#ಅನ್ತರ್ಭಾವ <string.h> /* memcpy */
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#ಅನ್ತರ್ಭಾವ <openssl/proverr.h>
#ಅನ್ತರ್ಭಾವ "crypto/sha.h"
#ಅನ್ತರ್ಭಾವ "internal/common.h" /* ossl_assert */

/* Returns the number of bytes required to store 'bits' into a byte array */
ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ get_encode_ಗಾತ್ರ(size_t ಬಿಟ್ಟುಗಳು)
{
    ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ cnt = 0, sz = ಗಾತ್ರ(size_t);

    ಆಗ (ಬಿಟ್ಟುಗಳು && (cnt < sz)) {
        ++cnt;
        ಬಿಟ್ಟುಗಳು >>= 8;
    }
    /* If bits is zero 1 byte is required */
    ಆದರೆ (cnt == 0)
        cnt = 1;
    ಹಿಂತಿರುಗಿ cnt;
}

/*
 * Convert an integer into bytes. The number of bytes is appended
 * to the end of the buffer.
 * Returns an array of bytes 'out' of size *out_len.
 *
 * e.g if bits = 32, out[2] = { 0x20, 0x01 }
 */
ಪೂರ್ಣಾಂಕ ossl_sp800_185_ಬಲ_encode(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು,
    size_t ಹೊರಹೋಗು_max_len, size_t *ಹೊರಹೋಗು_len,
    size_t ಬಿಟ್ಟುಗಳು)
{
    ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ len = get_encode_ಗಾತ್ರ(ಬಿಟ್ಟುಗಳು);
    ಪೂರ್ಣಾಂಕ i;

    ಆದರೆ (len >= ಹೊರಹೋಗು_max_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_ಉದ್ದಳತೆ_TOO_LARGE);
        ಹಿಂತಿರುಗಿ 0;
    }

    /* MSB's are at the start of the bytes array */
    ಗಾಗಿ (i = len - 1; i >= 0; --i) {
        ಹೊರಹೋಗು[i] = (ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)(ಬಿಟ್ಟುಗಳು & 0xFF);
        ಬಿಟ್ಟುಗಳು >>= 8;
    }
    /* Tack the length onto the end */
    ಹೊರಹೋಗು[len] = (ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)len;

    /* The Returned length includes the tacked on byte */
    *ಹೊರಹೋಗು_len = len + 1;
    ಹಿಂತಿರುಗಿ 1;
}

/*
 * Encodes a string with a left encoded length added. Note that the
 * in_len is converted to bits (* 8).
 *
 * e.g- in="KMAC" gives out[6] = { 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43 }
 *                                 len   bits    K     M     A     C
 */
ಪೂರ್ಣಾಂಕ ossl_sp800_185_encode_string(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು,
    size_t ಹೊರಹೋಗು_max_len, size_t *ಹೊರಹೋಗು_len,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಒಳ, size_t ಒಳ_len)
{
    ಆದರೆ (ಒಳ == ಖಾಲಿ) {
        *ಹೊರಹೋಗು_len = 0;
    } ಇಲ್ಲದಿದ್ದರೆ {
        size_t i, ಬಿಟ್ಟುಗಳು, len, sz;

        ಬಿಟ್ಟುಗಳು = 8 * ಒಳ_len;
        len = get_encode_ಗಾತ್ರ(ಬಿಟ್ಟುಗಳು);
        sz = 1 + len + ಒಳ_len;

        ಆದರೆ (sz > ಹೊರಹೋಗು_max_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_ಉದ್ದಳತೆ_TOO_LARGE);
            ಹಿಂತಿರುಗಿ 0;
        }

        ಹೊರಹೋಗು[0] = (ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)len;
        ಗಾಗಿ (i = len; i > 0; --i) {
            ಹೊರಹೋಗು[i] = (ಬಿಟ್ಟುಗಳು & 0xFF);
            ಬಿಟ್ಟುಗಳು >>= 8;
        }
        ಸ್ಮರಣೆ_ನಕಲು(ಹೊರಹೋಗು + len + 1, ಒಳ, ಒಳ_len);
        *ಹೊರಹೋಗು_len = sz;
    }
    ಹಿಂತಿರುಗಿ 1;
}

/*
 * Returns a zero padded encoding of the inputs in1 and an optional
 * in2 (can be NULL). The padded output must be a multiple of the blocksize 'w'.
 * The value of w is in bytes (< 256).
 *
 * The returned output is:
 *    zero_padded(multiple of w, (left_encode(w) || in1 [|| in2])
 */
ಪೂರ್ಣಾಂಕ ossl_sp800_185_bytepad(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು, size_t ಹೊರಹೋಗು_len_max, size_t *ಹೊರಹೋಗು_len,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *in1, size_t in1_len,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *in2, size_t in2_len,
    size_t w)
{
    size_t len;
    ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *p = ಹೊರಹೋಗು;
    size_t sz;

    ಆದರೆ (!ossl_assert(w <= 255))
        ಹಿಂತಿರುಗಿ 0;
    sz = (2 + in1_len + (in2 != ಖಾಲಿ ? in2_len : 0) + w - 1) / w * w;
    ಆದರೆ (ಹೊರಹೋಗು_len_max != 0 && sz > ಹೊರಹೋಗು_len_max)
        ಹಿಂತಿರುಗಿ 0;

    ಆದರೆ (ಹೊರಹೋಗು == ಖಾಲಿ) {
        ಆದರೆ (ಹೊರಹೋಗು_len == ಖಾಲಿ) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            ಹಿಂತಿರುಗಿ 0;
        }
        *ಹೊರಹೋಗು_len = sz;
        ಹಿಂತಿರುಗಿ 1;
    }

    /* Left encoded w */
    *p++ = 1;
    *p++ = (ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)w;
    /* || in1 */
    ಸ್ಮರಣೆ_ನಕಲು(p, in1, in1_len);
    p += in1_len;
    /* [ || in2 ] */
    ಆದರೆ (in2 != ಖಾಲಿ && in2_len > 0) {
        ಸ್ಮರಣೆ_ನಕಲು(p, in2, in2_len);
        p += in2_len;
    }
    /* Figure out the pad size (divisible by w) */
    len = p - ಹೊರಹೋಗು;
    /* zero pad the end of the buffer */
    ಆದರೆ (sz != len)
        memset(p, 0, sz - len);
    ಆದರೆ (ಹೊರಹೋಗು_len != ಖಾಲಿ)
        *ಹೊರಹೋಗು_len = sz;
    ಹಿಂತಿರುಗಿ 1;
}
