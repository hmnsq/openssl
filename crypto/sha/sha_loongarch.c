/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#ضمن "arch/loongarch_arch.h"

فراغ sha256_block_data_order_la64v100(فراغ *ctx, ثابت فراغ *in, size_t num);
فراغ sha256_block_data_order_lsx(فراغ *ctx, ثابت فراغ *in, size_t num);
فراغ sha256_block_data_order(فراغ *ctx, ثابت فراغ *in, size_t num);

فراغ sha256_block_data_order(فراغ *ctx, ثابت فراغ *in, size_t num)
{
    ܐܢ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_block_data_order_lsx(ctx, in, num);
    } ܐܚܪܢܐ {
        sha256_block_data_order_la64v100(ctx, in, num);
    }
}

فراغ sha512_block_data_order_la64v100(فراغ *ctx, ثابت فراغ *in, size_t num);
فراغ sha512_block_data_order_lsx(فراغ *ctx, ثابت فراغ *in, size_t num);
فراغ sha512_block_data_order(فراغ *ctx, ثابت فراغ *in, size_t num);

فراغ sha512_block_data_order(فراغ *ctx, ثابت فراغ *in, size_t num)
{
    ܐܢ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_block_data_order_lsx(ctx, in, num);
    } ܐܚܪܢܐ {
        sha512_block_data_order_la64v100(ctx, in, num);
    }
}
