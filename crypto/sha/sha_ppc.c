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

خالی sha256_بلاک_p8(خالی *ctx, ثابت خالی *inp, size_t len);
خالی sha256_بلاک_ppc(خالی *ctx, ثابت خالی *inp, size_t len);
خالی sha256_بلاک_ڈیٹا_ترتیب(خالی *ctx, ثابت خالی *inp, size_t len);
خالی sha256_بلاک_ڈیٹا_ترتیب(خالی *ctx, ثابت خالی *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_بلاک_p8(ctx, inp, len) : sha256_بلاک_ppc(ctx, inp, len);
}

خالی sha512_بلاک_p8(خالی *ctx, ثابت خالی *inp, size_t len);
خالی sha512_بلاک_ppc(خالی *ctx, ثابت خالی *inp, size_t len);
خالی sha512_بلاک_ڈیٹا_ترتیب(خالی *ctx, ثابت خالی *inp, size_t len);
خالی sha512_بلاک_ڈیٹا_ترتیب(خالی *ctx, ثابت خالی *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_بلاک_p8(ctx, inp, len) : sha512_بلاک_ppc(ctx, inp, len);
}
