/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#شامل "arch/loongarch_arch.h"

تهی sha256_block_data_order_la64v100(تهی *ctx, ثابت تهی *in, size_t رقم);
تهی sha256_block_data_order_lsx(تهی *ctx, ثابت تهی *in, size_t رقم);
تهی sha256_block_data_order(تهی *ctx, ثابت تهی *in, size_t رقم);

تهی sha256_block_data_order(تهی *ctx, ثابت تهی *in, size_t رقم)
{
    اگر (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_block_data_order_lsx(ctx, in, رقم);
    } وگرنه {
        sha256_block_data_order_la64v100(ctx, in, رقم);
    }
}

تهی sha512_block_data_order_la64v100(تهی *ctx, ثابت تهی *in, size_t رقم);
تهی sha512_block_data_order_lsx(تهی *ctx, ثابت تهی *in, size_t رقم);
تهی sha512_block_data_order(تهی *ctx, ثابت تهی *in, size_t رقم);

تهی sha512_block_data_order(تهی *ctx, ثابت تهی *in, size_t رقم)
{
    اگر (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_block_data_order_lsx(ctx, in, رقم);
    } وگرنه {
        sha512_block_data_order_la64v100(ctx, in, رقم);
    }
}
