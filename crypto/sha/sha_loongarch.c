/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#شامل "arch/loongarch_arch.h"

خالی sha256_بلاک_ڈیٹا_ترتیب_la64v100(خالی *ctx, ثابت خالی *اندر, size_t عدد);
خالی sha256_بلاک_ڈیٹا_ترتیب_lsx(خالی *ctx, ثابت خالی *اندر, size_t عدد);
خالی sha256_بلاک_ڈیٹا_ترتیب(خالی *ctx, ثابت خالی *اندر, size_t عدد);

خالی sha256_بلاک_ڈیٹا_ترتیب(خالی *ctx, ثابت خالی *اندر, size_t عدد)
{
    اگر (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_بلاک_ڈیٹا_ترتیب_lsx(ctx, اندر, عدد);
    } ورنہ {
        sha256_بلاک_ڈیٹا_ترتیب_la64v100(ctx, اندر, عدد);
    }
}

خالی sha512_بلاک_ڈیٹا_ترتیب_la64v100(خالی *ctx, ثابت خالی *اندر, size_t عدد);
خالی sha512_بلاک_ڈیٹا_ترتیب_lsx(خالی *ctx, ثابت خالی *اندر, size_t عدد);
خالی sha512_بلاک_ڈیٹا_ترتیب(خالی *ctx, ثابت خالی *اندر, size_t عدد);

خالی sha512_بلاک_ڈیٹا_ترتیب(خالی *ctx, ثابت خالی *اندر, size_t عدد)
{
    اگر (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_بلاک_ڈیٹا_ترتیب_lsx(ctx, اندر, عدد);
    } ورنہ {
        sha512_بلاک_ڈیٹا_ترتیب_la64v100(ctx, اندر, عدد);
    }
}
