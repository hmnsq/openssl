/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#அந்தர்பாவ "arch/loongarch_arch.h"

வெறுமை sha256_block_data_order_la64v100(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);
வெறுமை sha256_block_data_order_lsx(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);
வெறுமை sha256_block_data_order(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);

வெறுமை sha256_block_data_order(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்)
{
    எனில் (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_block_data_order_lsx(ctx, in, இலக்கம்);
    } இல்லையெனில் {
        sha256_block_data_order_la64v100(ctx, in, இலக்கம்);
    }
}

வெறுமை sha512_block_data_order_la64v100(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);
வெறுமை sha512_block_data_order_lsx(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);
வெறுமை sha512_block_data_order(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்);

வெறுமை sha512_block_data_order(வெறுமை *ctx, மாறிலி வெறுமை *in, size_t இலக்கம்)
{
    எனில் (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_block_data_order_lsx(ctx, in, இலக்கம்);
    } இல்லையெனில் {
        sha512_block_data_order_la64v100(ctx, in, இலக்கம்);
    }
}
