/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#અન્તર્ભાવ "arch/loongarch_arch.h"

શૂન્ય sha256_block_data_order_la64v100(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);
શૂન્ય sha256_block_data_order_lsx(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);
શૂન્ય sha256_block_data_order(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);

શૂન્ય sha256_block_data_order(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક)
{
    જો (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_block_data_order_lsx(ctx, in, અંક);
    } નહીંતર {
        sha256_block_data_order_la64v100(ctx, in, અંક);
    }
}

શૂન્ય sha512_block_data_order_la64v100(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);
શૂન્ય sha512_block_data_order_lsx(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);
શૂન્ય sha512_block_data_order(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક);

શૂન્ય sha512_block_data_order(શૂન્ય *ctx, અચલ શૂન્ય *in, size_t અંક)
{
    જો (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_block_data_order_lsx(ctx, in, અંક);
    } નહીંતર {
        sha512_block_data_order_la64v100(ctx, in, અંક);
    }
}
