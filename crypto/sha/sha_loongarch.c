/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#ಅನ್ತರ್ಭಾವ "arch/loongarch_arch.h"

ಶೂನ್ಯ sha256_block_data_order_la64v100(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha256_block_data_order_lsx(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha256_block_data_order(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);

ಶೂನ್ಯ sha256_block_data_order(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ)
{
    ಯದಿ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_block_data_order_lsx(ctx, in, ಅಂಕೆ);
    } ಅನ್ಯಥಾ {
        sha256_block_data_order_la64v100(ctx, in, ಅಂಕೆ);
    }
}

ಶೂನ್ಯ sha512_block_data_order_la64v100(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha512_block_data_order_lsx(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha512_block_data_order(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ);

ಶೂನ್ಯ sha512_block_data_order(ಶೂನ್ಯ *ctx, ಧ್ರುವ ಶೂನ್ಯ *in, size_t ಅಂಕೆ)
{
    ಯದಿ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_block_data_order_lsx(ctx, in, ಅಂಕೆ);
    } ಅನ್ಯಥಾ {
        sha512_block_data_order_la64v100(ctx, in, ಅಂಕೆ);
    }
}
