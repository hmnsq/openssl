/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#समावेश "arch/riscv_arch.h"

व्योम sha256_block_तथ्य_order_zvkb_zvknha_or_zvknhb(व्योम *ctx, स्थिर व्योम *in,
    माप_प्रकार अंक);
व्योम sha256_block_तथ्य_order_zbb(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);
व्योम sha256_block_तथ्य_order_riscv64(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);
व्योम sha256_block_तथ्य_order(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);

व्योम sha256_block_तथ्य_order(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक)
{
    अगर (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_block_तथ्य_order_zvkb_zvknha_or_zvknhb(ctx, in, अंक);
    } अन्यथा अगर (RISCV_HAS_ZBB()) {
        sha256_block_तथ्य_order_zbb(ctx, in, अंक);
    } अन्यथा {
        sha256_block_तथ्य_order_riscv64(ctx, in, अंक);
    }
}

व्योम sha512_block_तथ्य_order_zvkb_zvknhb(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);
व्योम sha512_block_तथ्य_order_zbb(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);
व्योम sha512_block_तथ्य_order_c(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);
व्योम sha512_block_तथ्य_order(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक);

व्योम sha512_block_तथ्य_order(व्योम *ctx, स्थिर व्योम *in, माप_प्रकार अंक)
{
    अगर (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_block_तथ्य_order_zvkb_zvknhb(ctx, in, अंक);
    } अन्यथा अगर (RISCV_HAS_ZBB()) {
        sha512_block_तथ्य_order_zbb(ctx, in, अंक);
    } अन्यथा {
        sha512_block_तथ्य_order_c(ctx, in, अंक);
    }
}
