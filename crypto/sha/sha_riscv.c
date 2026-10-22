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

शून्य sha256_block_data_order_zvkb_zvknha_or_zvknhb(शून्य *ctx, ध्रुव शून्य *in,
    size_t अंक);
शून्य sha256_block_data_order_zbb(शून्य *ctx, ध्रुव शून्य *in, size_t अंक);
शून्य sha256_block_data_order_riscv64(शून्य *ctx, ध्रुव शून्य *in, size_t अंक);
शून्य sha256_block_data_order(शून्य *ctx, ध्रुव शून्य *in, size_t अंक);

शून्य sha256_block_data_order(शून्य *ctx, ध्रुव शून्य *in, size_t अंक)
{
    यदि (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_block_data_order_zvkb_zvknha_or_zvknhb(ctx, in, अंक);
    } अन्यथा यदि (RISCV_HAS_ZBB()) {
        sha256_block_data_order_zbb(ctx, in, अंक);
    } अन्यथा {
        sha256_block_data_order_riscv64(ctx, in, अंक);
    }
}

शून्य sha512_block_data_order_zvkb_zvknhb(शून्य *ctx, ध्रुव शून्य *in, size_t अंक);
शून्य sha512_block_data_order_zbb(शून्य *ctx, ध्रुव शून्य *in, size_t अंक);
शून्य sha512_block_data_order_c(शून्य *ctx, ध्रुव शून्य *in, size_t अंक);
शून्य sha512_block_data_order(शून्य *ctx, ध्रुव शून्य *in, size_t अंक);

शून्य sha512_block_data_order(शून्य *ctx, ध्रुव शून्य *in, size_t अंक)
{
    यदि (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_block_data_order_zvkb_zvknhb(ctx, in, अंक);
    } अन्यथा यदि (RISCV_HAS_ZBB()) {
        sha512_block_data_order_zbb(ctx, in, अंक);
    } अन्यथा {
        sha512_block_data_order_c(ctx, in, अंक);
    }
}
