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

فراغ sha256_بلاک_معلومات_ترتیب_zvkb_zvknha_or_zvknhb(فراغ *ctx, ثابت فراغ *دننه,
    size_t عدد);
فراغ sha256_بلاک_معلومات_ترتیب_zbb(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);
فراغ sha256_بلاک_معلومات_ترتیب_riscv64(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);
فراغ sha256_بلاک_معلومات_ترتیب(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);

فراغ sha256_بلاک_معلومات_ترتیب(فراغ *ctx, ثابت فراغ *دننه, size_t عدد)
{
    إذا (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_بلاک_معلومات_ترتیب_zvkb_zvknha_or_zvknhb(ctx, دننه, عدد);
    } وإلا إذا (RISCV_HAS_ZBB()) {
        sha256_بلاک_معلومات_ترتیب_zbb(ctx, دننه, عدد);
    } وإلا {
        sha256_بلاک_معلومات_ترتیب_riscv64(ctx, دننه, عدد);
    }
}

فراغ sha512_بلاک_معلومات_ترتیب_zvkb_zvknhb(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);
فراغ sha512_بلاک_معلومات_ترتیب_zbb(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);
فراغ sha512_بلاک_معلومات_ترتیب_c(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);
فراغ sha512_بلاک_معلومات_ترتیب(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);

فراغ sha512_بلاک_معلومات_ترتیب(فراغ *ctx, ثابت فراغ *دننه, size_t عدد)
{
    إذا (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_بلاک_معلومات_ترتیب_zvkb_zvknhb(ctx, دننه, عدد);
    } وإلا إذا (RISCV_HAS_ZBB()) {
        sha512_بلاک_معلومات_ترتیب_zbb(ctx, دننه, عدد);
    } وإلا {
        sha512_بلاک_معلومات_ترتیب_c(ctx, دننه, عدد);
    }
}
