/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ <openssl/opensslconf.h>
#অন্তর্ভাৱ <openssl/sha.h>
#অন্তর্ভাৱ "arch/riscv_arch.h"

শূন্য sha256_block_data_order_zvkb_zvknha_or_zvknhb(শূন্য *ctx, ধ্রুৱ শূন্য *in,
    size_t অঙ্ক);
শূন্য sha256_block_data_order_zbb(শূন্য *ctx, ধ্রুৱ শূন্য *in, size_t অঙ্ক);
শূন্য sha256_block_data_order_riscv64(শূন্য *ctx, ধ্রুৱ শূন্য *in, size_t অঙ্ক);
শূন্য sha256_block_data_order(শূন্য *ctx, ধ্রুৱ শূন্য *in, size_t অঙ্ক);

শূন্য sha256_block_data_order(শূন্য *ctx, ধ্রুৱ শূন্য *in, size_t অঙ্ক)
{
    যদি (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_block_data_order_zvkb_zvknha_or_zvknhb(ctx, in, অঙ্ক);
    } অন্যথা যদি (RISCV_HAS_ZBB()) {
        sha256_block_data_order_zbb(ctx, in, অঙ্ক);
    } অন্যথা {
        sha256_block_data_order_riscv64(ctx, in, অঙ্ক);
    }
}

শূন্য sha512_block_data_order_zvkb_zvknhb(শূন্য *ctx, ধ্রুৱ শূন্য *in, size_t অঙ্ক);
শূন্য sha512_block_data_order_zbb(শূন্য *ctx, ধ্রুৱ শূন্য *in, size_t অঙ্ক);
শূন্য sha512_block_data_order_c(শূন্য *ctx, ধ্রুৱ শূন্য *in, size_t অঙ্ক);
শূন্য sha512_block_data_order(শূন্য *ctx, ধ্রুৱ শূন্য *in, size_t অঙ্ক);

শূন্য sha512_block_data_order(শূন্য *ctx, ধ্রুৱ শূন্য *in, size_t অঙ্ক)
{
    যদি (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_block_data_order_zvkb_zvknhb(ctx, in, অঙ্ক);
    } অন্যথা যদি (RISCV_HAS_ZBB()) {
        sha512_block_data_order_zbb(ctx, in, অঙ্ক);
    } অন্যথা {
        sha512_block_data_order_c(ctx, in, অঙ্ক);
    }
}
