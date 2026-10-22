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
स्थिर अचिन्हित पूर्णाङ्क get_encode_size(माप_प्रकार bits)
{
    अचिन्हित पूर्णाङ्क cnt = 0, sz = परिमाण(माप_प्रकार);

    जबसम्म (bits && (cnt < sz)) {
        ++cnt;
        bits >>= 8;
    }
    /* If bits is zero 1 byte is required */
    यदि (cnt == 0)
        cnt = 1;
    फर्काऊ cnt;
}

/*
 * Convert an integer into bytes. The number of bytes is appended
 * to the end of the buffer.
 * Returns an array of bytes 'out' of size *out_len.
 *
 * e.g if bits = 32, out[2] = { 0x20, 0x01 }
 */
पूर्णाङ्क ossl_sp800_185_दायाँ_encode(अचिन्हित वर्ण *out,
    माप_प्रकार out_max_len, माप_प्रकार *out_len,
    माप_प्रकार bits)
{
    अचिन्हित पूर्णाङ्क len = get_encode_size(bits);
    पूर्णाङ्क i;

    यदि (len >= out_max_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
        फर्काऊ 0;
    }

    /* MSB's are at the start of the bytes array */
    लागि (i = len - 1; i >= 0; --i) {
        out[i] = (अचिन्हित वर्ण)(bits & 0xFF);
        bits >>= 8;
    }
    /* Tack the length onto the end */
    out[len] = (अचिन्हित वर्ण)len;

    /* The Returned length includes the tacked on byte */
    *out_len = len + 1;
    फर्काऊ 1;
}

/*
 * Encodes a string with a left encoded length added. Note that the
 * in_len is converted to bits (* 8).
 *
 * e.g- in="KMAC" gives out[6] = { 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43 }
 *                                 len   bits    K     M     A     C
 */
पूर्णाङ्क ossl_sp800_185_encode_string(अचिन्हित वर्ण *out,
    माप_प्रकार out_max_len, माप_प्रकार *out_len,
    अचर अचिन्हित वर्ण *in, माप_प्रकार in_len)
{
    यदि (in == रिक्त) {
        *out_len = 0;
    } अन्यथा {
        माप_प्रकार i, bits, len, sz;

        bits = 8 * in_len;
        len = get_encode_size(bits);
        sz = 1 + len + in_len;

        यदि (sz > out_max_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE);
            फर्काऊ 0;
        }

        out[0] = (अचिन्हित वर्ण)len;
        लागि (i = len; i > 0; --i) {
            out[i] = (bits & 0xFF);
            bits >>= 8;
        }
        स_नकल(out + len + 1, in, in_len);
        *out_len = sz;
    }
    फर्काऊ 1;
}

/*
 * Returns a zero padded encoding of the inputs in1 and an optional
 * in2 (can be NULL). The padded output must be a multiple of the blocksize 'w'.
 * The value of w is in bytes (< 256).
 *
 * The returned output is:
 *    zero_padded(multiple of w, (left_encode(w) || in1 [|| in2])
 */
पूर्णाङ्क ossl_sp800_185_bytepad(अचिन्हित वर्ण *out, माप_प्रकार out_len_max, माप_प्रकार *out_len,
    अचर अचिन्हित वर्ण *in1, माप_प्रकार in1_len,
    अचर अचिन्हित वर्ण *in2, माप_प्रकार in2_len,
    माप_प्रकार w)
{
    माप_प्रकार len;
    अचिन्हित वर्ण *p = out;
    माप_प्रकार sz;

    यदि (!ossl_assert(w <= 255))
        फर्काऊ 0;
    sz = (2 + in1_len + (in2 != रिक्त ? in2_len : 0) + w - 1) / w * w;
    यदि (out_len_max != 0 && sz > out_len_max)
        फर्काऊ 0;

    यदि (out == रिक्त) {
        यदि (out_len == रिक्त) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            फर्काऊ 0;
        }
        *out_len = sz;
        फर्काऊ 1;
    }

    /* Left encoded w */
    *p++ = 1;
    *p++ = (अचिन्हित वर्ण)w;
    /* || in1 */
    स_नकल(p, in1, in1_len);
    p += in1_len;
    /* [ || in2 ] */
    यदि (in2 != रिक्त && in2_len > 0) {
        स_नकल(p, in2, in2_len);
        p += in2_len;
    }
    /* Figure out the pad size (divisible by w) */
    len = p - out;
    /* zero pad the end of the buffer */
    यदि (sz != len)
        स_रखो(p, 0, sz - len);
    यदि (out_len != रिक्त)
        *out_len = sz;
    फर्काऊ 1;
}
