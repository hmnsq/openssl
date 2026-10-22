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

فراغ sha256_block_data_order_zvkb_zvknha_or_zvknhb(فراغ *ctx, ثابت فراغ *in,
    size_t لمب);
فراغ sha256_block_data_order_zbb(فراغ *ctx, ثابت فراغ *in, size_t لمب);
فراغ sha256_block_data_order_riscv64(فراغ *ctx, ثابت فراغ *in, size_t لمب);
فراغ sha256_block_data_order(فراغ *ctx, ثابت فراغ *in, size_t لمب);

فراغ sha256_block_data_order(فراغ *ctx, ثابت فراغ *in, size_t لمب)
{
    إذا (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_block_data_order_zvkb_zvknha_or_zvknhb(ctx, in, لمب);
    } وإلا إذا (RISCV_HAS_ZBB()) {
        sha256_block_data_order_zbb(ctx, in, لمب);
    } وإلا {
        sha256_block_data_order_riscv64(ctx, in, لمب);
    }
}

فراغ sha512_block_data_order_zvkb_zvknhb(فراغ *ctx, ثابت فراغ *in, size_t لمب);
فراغ sha512_block_data_order_zbb(فراغ *ctx, ثابت فراغ *in, size_t لمب);
فراغ sha512_block_data_order_c(فراغ *ctx, ثابت فراغ *in, size_t لمب);
فراغ sha512_block_data_order(فراغ *ctx, ثابت فراغ *in, size_t لمب);

فراغ sha512_block_data_order(فراغ *ctx, ثابت فراغ *in, size_t لمب)
{
    إذا (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_block_data_order_zvkb_zvknhb(ctx, in, لمب);
    } وإلا إذا (RISCV_HAS_ZBB()) {
        sha512_block_data_order_zbb(ctx, in, لمب);
    } وإلا {
        sha512_block_data_order_c(ctx, in, لمب);
    }
}
