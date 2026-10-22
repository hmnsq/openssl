/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#شامل "arch/riscv_arch.h"

خالی sha256_بلاک_ڈیٹا_ترتیب_zvkb_zvknha_or_zvknhb(خالی *ctx, ثابت خالی *اندر,
    size_t عدد);
خالی sha256_بلاک_ڈیٹا_ترتیب_zbb(خالی *ctx, ثابت خالی *اندر, size_t عدد);
خالی sha256_بلاک_ڈیٹا_ترتیب_riscv64(خالی *ctx, ثابت خالی *اندر, size_t عدد);
خالی sha256_بلاک_ڈیٹا_ترتیب(خالی *ctx, ثابت خالی *اندر, size_t عدد);

خالی sha256_بلاک_ڈیٹا_ترتیب(خالی *ctx, ثابت خالی *اندر, size_t عدد)
{
    اگر (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_بلاک_ڈیٹا_ترتیب_zvkb_zvknha_or_zvknhb(ctx, اندر, عدد);
    } ورنہ اگر (RISCV_HAS_ZBB()) {
        sha256_بلاک_ڈیٹا_ترتیب_zbb(ctx, اندر, عدد);
    } ورنہ {
        sha256_بلاک_ڈیٹا_ترتیب_riscv64(ctx, اندر, عدد);
    }
}

خالی sha512_بلاک_ڈیٹا_ترتیب_zvkb_zvknhb(خالی *ctx, ثابت خالی *اندر, size_t عدد);
خالی sha512_بلاک_ڈیٹا_ترتیب_zbb(خالی *ctx, ثابت خالی *اندر, size_t عدد);
خالی sha512_بلاک_ڈیٹا_ترتیب_c(خالی *ctx, ثابت خالی *اندر, size_t عدد);
خالی sha512_بلاک_ڈیٹا_ترتیب(خالی *ctx, ثابت خالی *اندر, size_t عدد);

خالی sha512_بلاک_ڈیٹا_ترتیب(خالی *ctx, ثابت خالی *اندر, size_t عدد)
{
    اگر (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_بلاک_ڈیٹا_ترتیب_zvkb_zvknhb(ctx, اندر, عدد);
    } ورنہ اگر (RISCV_HAS_ZBB()) {
        sha512_بلاک_ڈیٹا_ترتیب_zbb(ctx, اندر, عدد);
    } ورنہ {
        sha512_بلاک_ڈیٹا_ترتیب_c(ctx, اندر, عدد);
    }
}
