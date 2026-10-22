/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव <openssl/opensslconf.h>
#अन्तर्भाव <openssl/sha.h>
#अन्तर्भाव "arch/riscv_arch.h"

शून्य sha256_खण्डम्_दत्त_क्रमः_zvkb_zvknha_or_zvknhb(शून्य *ctx, ध्रुव शून्य *अन्तर्,
    size_t अङ्कः);
शून्य sha256_खण्डम्_दत्त_क्रमः_zbb(शून्य *ctx, ध्रुव शून्य *अन्तर्, size_t अङ्कः);
शून्य sha256_खण्डम्_दत्त_क्रमः_riscv64(शून्य *ctx, ध्रुव शून्य *अन्तर्, size_t अङ्कः);
शून्य sha256_खण्डम्_दत्त_क्रमः(शून्य *ctx, ध्रुव शून्य *अन्तर्, size_t अङ्कः);

शून्य sha256_खण्डम्_दत्त_क्रमः(शून्य *ctx, ध्रुव शून्य *अन्तर्, size_t अङ्कः)
{
    यदि (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_खण्डम्_दत्त_क्रमः_zvkb_zvknha_or_zvknhb(ctx, अन्तर्, अङ्कः);
    } अन्यथा यदि (RISCV_HAS_ZBB()) {
        sha256_खण्डम्_दत्त_क्रमः_zbb(ctx, अन्तर्, अङ्कः);
    } अन्यथा {
        sha256_खण्डम्_दत्त_क्रमः_riscv64(ctx, अन्तर्, अङ्कः);
    }
}

शून्य sha512_खण्डम्_दत्त_क्रमः_zvkb_zvknhb(शून्य *ctx, ध्रुव शून्य *अन्तर्, size_t अङ्कः);
शून्य sha512_खण्डम्_दत्त_क्रमः_zbb(शून्य *ctx, ध्रुव शून्य *अन्तर्, size_t अङ्कः);
शून्य sha512_खण्डम्_दत्त_क्रमः_c(शून्य *ctx, ध्रुव शून्य *अन्तर्, size_t अङ्कः);
शून्य sha512_खण्डम्_दत्त_क्रमः(शून्य *ctx, ध्रुव शून्य *अन्तर्, size_t अङ्कः);

शून्य sha512_खण्डम्_दत्त_क्रमः(शून्य *ctx, ध्रुव शून्य *अन्तर्, size_t अङ्कः)
{
    यदि (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_खण्डम्_दत्त_क्रमः_zvkb_zvknhb(ctx, अन्तर्, अङ्कः);
    } अन्यथा यदि (RISCV_HAS_ZBB()) {
        sha512_खण्डम्_दत्त_क्रमः_zbb(ctx, अन्तर्, अङ्कः);
    } अन्यथा {
        sha512_खण्डम्_दत्त_क्रमः_c(ctx, अन्तर्, अङ्कः);
    }
}
