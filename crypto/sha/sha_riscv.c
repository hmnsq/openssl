/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ <openssl/opensslconf.h>
#ଅନ୍ତର୍ଭାଵ <openssl/sha.h>
#ଅନ୍ତର୍ଭାଵ "arch/riscv_arch.h"

ଶୂନ୍ୟ sha256_block_data_order_zvkb_zvknha_or_zvknhb(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in,
    size_t ଅଙ୍କ);
ଶୂନ୍ୟ sha256_block_data_order_zbb(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);
ଶୂନ୍ୟ sha256_block_data_order_riscv64(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);
ଶୂନ୍ୟ sha256_block_data_order(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);

ଶୂନ୍ୟ sha256_block_data_order(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ)
{
    ଯଦି (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_block_data_order_zvkb_zvknha_or_zvknhb(ctx, in, ଅଙ୍କ);
    } ଅନ୍ୟଥା ଯଦି (RISCV_HAS_ZBB()) {
        sha256_block_data_order_zbb(ctx, in, ଅଙ୍କ);
    } ଅନ୍ୟଥା {
        sha256_block_data_order_riscv64(ctx, in, ଅଙ୍କ);
    }
}

ଶୂନ୍ୟ sha512_block_data_order_zvkb_zvknhb(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);
ଶୂନ୍ୟ sha512_block_data_order_zbb(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);
ଶୂନ୍ୟ sha512_block_data_order_c(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);
ଶୂନ୍ୟ sha512_block_data_order(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);

ଶୂନ୍ୟ sha512_block_data_order(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ)
{
    ଯଦି (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_block_data_order_zvkb_zvknhb(ctx, in, ଅଙ୍କ);
    } ଅନ୍ୟଥା ଯଦି (RISCV_HAS_ZBB()) {
        sha512_block_data_order_zbb(ctx, in, ଅଙ୍କ);
    } ଅନ୍ୟଥା {
        sha512_block_data_order_c(ctx, in, ଅଙ୍କ);
    }
}
