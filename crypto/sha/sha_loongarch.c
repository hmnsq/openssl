/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश <openssl/opensslconf.h>
#समावेश <openssl/sha.h>
#समावेश "arch/loongarch_arch.h"

व्योम sha256_block_तथ्य_order_la64v100(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);
व्योम sha256_block_तथ्य_order_lsx(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);
व्योम sha256_block_तथ्य_order(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);

व्योम sha256_block_तथ्य_order(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक)
{
    अगर (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_block_तथ्य_order_lsx(ctx, in, अंक);
    } अन्यथा {
        sha256_block_तथ्य_order_la64v100(ctx, in, अंक);
    }
}

व्योम sha512_block_तथ्य_order_la64v100(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);
व्योम sha512_block_तथ्य_order_lsx(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);
व्योम sha512_block_तथ्य_order(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);

व्योम sha512_block_तथ्य_order(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक)
{
    अगर (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_block_तथ्य_order_lsx(ctx, in, अंक);
    } अन्यथा {
        sha512_block_तथ्य_order_la64v100(ctx, in, अंक);
    }
}
