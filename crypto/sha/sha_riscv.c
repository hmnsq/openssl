/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن <openssl/opensslconf.h>
#ضمن <openssl/sha.h>
#ضمن "arch/riscv_arch.h"

فراغ sha256_بلاڪ_معلومات_ترتيب_zvkb_zvknha_or_zvknhb(فراغ *ctx, ثابت فراغ *اندريون,
    size_t انگ);
فراغ sha256_بلاڪ_معلومات_ترتيب_zbb(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);
فراغ sha256_بلاڪ_معلومات_ترتيب_riscv64(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);
فراغ sha256_بلاڪ_معلومات_ترتيب(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);

فراغ sha256_بلاڪ_معلومات_ترتيب(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ)
{
    إذا (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_بلاڪ_معلومات_ترتيب_zvkb_zvknha_or_zvknhb(ctx, اندريون, انگ);
    } وإلا إذا (RISCV_HAS_ZBB()) {
        sha256_بلاڪ_معلومات_ترتيب_zbb(ctx, اندريون, انگ);
    } وإلا {
        sha256_بلاڪ_معلومات_ترتيب_riscv64(ctx, اندريون, انگ);
    }
}

فراغ sha512_بلاڪ_معلومات_ترتيب_zvkb_zvknhb(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);
فراغ sha512_بلاڪ_معلومات_ترتيب_zbb(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);
فراغ sha512_بلاڪ_معلومات_ترتيب_c(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);
فراغ sha512_بلاڪ_معلومات_ترتيب(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);

فراغ sha512_بلاڪ_معلومات_ترتيب(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ)
{
    إذا (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_بلاڪ_معلومات_ترتيب_zvkb_zvknhb(ctx, اندريون, انگ);
    } وإلا إذا (RISCV_HAS_ZBB()) {
        sha512_بلاڪ_معلومات_ترتيب_zbb(ctx, اندريون, انگ);
    } وإلا {
        sha512_بلاڪ_معلومات_ترتيب_c(ctx, اندريون, انگ);
    }
}
