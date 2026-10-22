/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ <openssl/opensslconf.h>
#அந்தர்பாவ <openssl/sha.h>
#அந்தர்பாவ "arch/riscv_arch.h"

வெறுமை sha256_block_data_order_zvkb_zvknha_or_zvknhb(வெறுமை *ctx, மாறிலி வெறுமை *in,
    size_t இலக்கம்);
வெறுமை sha256_block_data_order_zbb(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);
வெறுமை sha256_block_data_order_riscv64(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);
வெறுமை sha256_block_data_order(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);

வெறுமை sha256_block_data_order(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்)
{
    எனில் (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_block_data_order_zvkb_zvknha_or_zvknhb(ctx, in, இலக்கம்);
    } இல்லையெனில் எனில் (RISCV_HAS_ZBB()) {
        sha256_block_data_order_zbb(ctx, in, இலக்கம்);
    } இல்லையெனில் {
        sha256_block_data_order_riscv64(ctx, in, இலக்கம்);
    }
}

வெறுமை sha512_block_data_order_zvkb_zvknhb(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);
வெறுமை sha512_block_data_order_zbb(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);
வெறுமை sha512_block_data_order_c(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);
வெறுமை sha512_block_data_order(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);

வெறுமை sha512_block_data_order(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்)
{
    எனில் (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_block_data_order_zvkb_zvknhb(ctx, in, இலக்கம்);
    } இல்லையெனில் எனில் (RISCV_HAS_ZBB()) {
        sha512_block_data_order_zbb(ctx, in, இலக்கம்);
    } இல்லையெனில் {
        sha512_block_data_order_c(ctx, in, இலக்கம்);
    }
}
