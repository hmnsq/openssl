/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#ଅନ୍ତର୍ଭାଵ "arch/loongarch_arch.h"

ଶୂନ୍ୟ sha256_block_data_order_la64v100(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);
ଶୂନ୍ୟ sha256_block_data_order_lsx(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);
ଶୂନ୍ୟ sha256_block_data_order(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);

ଶୂନ୍ୟ sha256_block_data_order(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ)
{
    ଯଦି (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_block_data_order_lsx(ctx, in, ଅଙ୍କ);
    } ଅନ୍ୟଥା {
        sha256_block_data_order_la64v100(ctx, in, ଅଙ୍କ);
    }
}

ଶୂନ୍ୟ sha512_block_data_order_la64v100(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);
ଶୂନ୍ୟ sha512_block_data_order_lsx(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);
ଶୂନ୍ୟ sha512_block_data_order(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ);

ଶୂନ୍ୟ sha512_block_data_order(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *in, size_t ଅଙ୍କ)
{
    ଯଦି (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_block_data_order_lsx(ctx, in, ଅଙ୍କ);
    } ଅନ୍ୟଥା {
        sha512_block_data_order_la64v100(ctx, in, ଅଙ୍କ);
    }
}
