/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ <openssl/opensslconf.h>
#અન્તર્ભાવ <openssl/sha.h>
#અન્તર્ભાવ "arch/riscv_arch.h"

શૂન્ય sha256_block_data_order_zvkb_zvknha_or_zvknhb(શૂન્ય *ctx, અચલ શૂન્ય *in,
    size_t અંક);
શૂન્ય sha256_block_data_order_zbb(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);
શૂન્ય sha256_block_data_order_riscv64(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);
શૂન્ય sha256_block_data_order(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);

શૂન્ય sha256_block_data_order(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક)
{
    જો (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_block_data_order_zvkb_zvknha_or_zvknhb(ctx, in, અંક);
    } નહીંતર જો (RISCV_HAS_ZBB()) {
        sha256_block_data_order_zbb(ctx, in, અંક);
    } નહીંતર {
        sha256_block_data_order_riscv64(ctx, in, અંક);
    }
}

શૂન્ય sha512_block_data_order_zvkb_zvknhb(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);
શૂન્ય sha512_block_data_order_zbb(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);
શૂન્ય sha512_block_data_order_c(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);
શૂન્ય sha512_block_data_order(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);

શૂન્ય sha512_block_data_order(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક)
{
    જો (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_block_data_order_zvkb_zvknhb(ctx, in, અંક);
    } નહીંતર જો (RISCV_HAS_ZBB()) {
        sha512_block_data_order_zbb(ctx, in, અંક);
    } નહીંતર {
        sha512_block_data_order_c(ctx, in, અંક);
    }
}
