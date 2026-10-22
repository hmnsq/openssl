/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#شامل <stdlib.h>
#شامل <string.h>

#شامل <openssl/opensslconf.h>
#شامل <openssl/sha.h>
#شامل "arch/riscv_arch.h"

تهی sha256_block_data_order_zvkb_zvknha_or_zvknhb(تهی *ctx, ثابت تهی *in,
    size_t رقم);
تهی sha256_block_data_order_zbb(تهی *ctx, ثابت تهی *in, size_t رقم);
تهی sha256_block_data_order_riscv64(تهی *ctx, ثابت تهی *in, size_t رقم);
تهی sha256_block_data_order(تهی *ctx, ثابت تهی *in, size_t رقم);

تهی sha256_block_data_order(تهی *ctx, ثابت تهی *in, size_t رقم)
{
    اگر (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_block_data_order_zvkb_zvknha_or_zvknhb(ctx, in, رقم);
    } وگرنه اگر (RISCV_HAS_ZBB()) {
        sha256_block_data_order_zbb(ctx, in, رقم);
    } وگرنه {
        sha256_block_data_order_riscv64(ctx, in, رقم);
    }
}

تهی sha512_block_data_order_zvkb_zvknhb(تهی *ctx, ثابت تهی *in, size_t رقم);
تهی sha512_block_data_order_zbb(تهی *ctx, ثابت تهی *in, size_t رقم);
تهی sha512_block_data_order_c(تهی *ctx, ثابت تهی *in, size_t رقم);
تهی sha512_block_data_order(تهی *ctx, ثابت تهی *in, size_t رقم);

تهی sha512_block_data_order(تهی *ctx, ثابت تهی *in, size_t رقم)
{
    اگر (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_block_data_order_zvkb_zvknhb(ctx, in, رقم);
    } وگرنه اگر (RISCV_HAS_ZBB()) {
        sha512_block_data_order_zbb(ctx, in, رقم);
    } وگرنه {
        sha512_block_data_order_c(ctx, in, رقم);
    }
}
