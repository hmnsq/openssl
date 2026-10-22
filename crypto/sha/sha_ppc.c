/*
 * Copyright 2009-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#समावेश "arch/ppc_arch.h"

व्योम sha256_block_p8(व्योम *ctx, स्थिर व्योम *inp, माप_प्रकार len);
व्योम sha256_block_ppc(व्योम *ctx, स्थिर व्योम *inp, माप_प्रकार len);
व्योम sha256_block_तथ्य_order(व्योम *ctx, स्थिर व्योम *inp, माप_प्रकार len);
व्योम sha256_block_तथ्य_order(व्योम *ctx, स्थिर व्योम *inp, माप_प्रकार len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_block_p8(ctx, inp, len) : sha256_block_ppc(ctx, inp, len);
}

व्योम sha512_block_p8(व्योम *ctx, स्थिर व्योम *inp, माप_प्रकार len);
व्योम sha512_block_ppc(व्योम *ctx, स्थिर व्योम *inp, माप_प्रकार len);
व्योम sha512_block_तथ्य_order(व्योम *ctx, स्थिर व्योम *inp, माप_प्रकार len);
व्योम sha512_block_तथ्य_order(व्योम *ctx, स्थिर व्योम *inp, माप_प्रकार len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_block_p8(ctx, inp, len) : sha512_block_ppc(ctx, inp, len);
}
