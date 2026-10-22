/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <openssl/opensslconf.h>
#ಅನ್ತರ್ಭಾವ <openssl/sha.h>
#ಅನ್ತರ್ಭಾವ "arch/riscv_arch.h"

ಶೂನ್ಯ sha256_block_data_order_zvkb_zvknha_or_zvknhb(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in,
    size_t ಅಂಕೆ);
ಶೂನ್ಯ sha256_block_data_order_zbb(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha256_block_data_order_riscv64(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha256_block_data_order(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);

ಶೂನ್ಯ sha256_block_data_order(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ)
{
    ಯದಿ (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_block_data_order_zvkb_zvknha_or_zvknhb(ctx, in, ಅಂಕೆ);
    } ಅನ್ಯಥಾ ಯದಿ (RISCV_HAS_ZBB()) {
        sha256_block_data_order_zbb(ctx, in, ಅಂಕೆ);
    } ಅನ್ಯಥಾ {
        sha256_block_data_order_riscv64(ctx, in, ಅಂಕೆ);
    }
}

ಶೂನ್ಯ sha512_block_data_order_zvkb_zvknhb(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha512_block_data_order_zbb(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha512_block_data_order_c(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha512_block_data_order(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);

ಶೂನ್ಯ sha512_block_data_order(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ)
{
    ಯದಿ (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_block_data_order_zvkb_zvknhb(ctx, in, ಅಂಕೆ);
    } ಅನ್ಯಥಾ ಯದಿ (RISCV_HAS_ZBB()) {
        sha512_block_data_order_zbb(ctx, in, ಅಂಕೆ);
    } ಅನ್ಯಥಾ {
        sha512_block_data_order_c(ctx, in, ಅಂಕೆ);
    }
}
