/*
 * Copyright 2009-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#شامل "arch/ppc_arch.h"

تهی sha256_block_p8(تهی *ctx, ثابت تهی *inp, size_t len);
تهی sha256_block_ppc(تهی *ctx, ثابت تهی *inp, size_t len);
تهی sha256_block_data_order(تهی *ctx, ثابت تهی *inp, size_t len);
تهی sha256_block_data_order(تهی *ctx, ثابت تهی *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_block_p8(ctx, inp, len) : sha256_block_ppc(ctx, inp, len);
}

تهی sha512_block_p8(تهی *ctx, ثابت تهی *inp, size_t len);
تهی sha512_block_ppc(تهی *ctx, ثابت تهی *inp, size_t len);
تهی sha512_block_data_order(تهی *ctx, ثابت تهی *inp, size_t len);
تهی sha512_block_data_order(تهی *ctx, ثابت تهی *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_block_p8(ctx, inp, len) : sha512_block_ppc(ctx, inp, len);
}
