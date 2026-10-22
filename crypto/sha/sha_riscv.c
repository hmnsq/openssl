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

فراغ sha256_بلوک_داده_ترتیب_zvkb_zvknha_or_zvknhb(فراغ *ctx, ثابت فراغ *درون,
    size_t رقم);
فراغ sha256_بلوک_داده_ترتیب_zbb(فراغ *ctx, ثابت فراغ *درون, size_t رقم);
فراغ sha256_بلوک_داده_ترتیب_riscv64(فراغ *ctx, ثابت فراغ *درون, size_t رقم);
فراغ sha256_بلوک_داده_ترتیب(فراغ *ctx, ثابت فراغ *درون, size_t رقم);

فراغ sha256_بلوک_داده_ترتیب(فراغ *ctx, ثابت فراغ *درون, size_t رقم)
{
    إذا (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_بلوک_داده_ترتیب_zvkb_zvknha_or_zvknhb(ctx, درون, رقم);
    } وإلا إذا (RISCV_HAS_ZBB()) {
        sha256_بلوک_داده_ترتیب_zbb(ctx, درون, رقم);
    } وإلا {
        sha256_بلوک_داده_ترتیب_riscv64(ctx, درون, رقم);
    }
}

فراغ sha512_بلوک_داده_ترتیب_zvkb_zvknhb(فراغ *ctx, ثابت فراغ *درون, size_t رقم);
فراغ sha512_بلوک_داده_ترتیب_zbb(فراغ *ctx, ثابت فراغ *درون, size_t رقم);
فراغ sha512_بلوک_داده_ترتیب_c(فراغ *ctx, ثابت فراغ *درون, size_t رقم);
فراغ sha512_بلوک_داده_ترتیب(فراغ *ctx, ثابت فراغ *درون, size_t رقم);

فراغ sha512_بلوک_داده_ترتیب(فراغ *ctx, ثابت فراغ *درون, size_t رقم)
{
    إذا (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_بلوک_داده_ترتیب_zvkb_zvknhb(ctx, درون, رقم);
    } وإلا إذا (RISCV_HAS_ZBB()) {
        sha512_بلوک_داده_ترتیب_zbb(ctx, درون, رقم);
    } وإلا {
        sha512_بلوک_داده_ترتیب_c(ctx, درون, رقم);
    }
}
