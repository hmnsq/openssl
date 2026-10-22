/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব <openssl/opensslconf.h>
#অন্তর্ভাব <openssl/sha.h>
#অন্তর্ভাব "arch/loongarch_arch.h"

শূন্য sha256_block_তথ্য_order_la64v100(শূন্য *ctx, ধ্রুবক শূন্য *in, size_t অঙ্ক);
শূন্য sha256_block_তথ্য_order_lsx(শূন্য *ctx, ধ্রুবক শূন্য *in, size_t অঙ্ক);
শূন্য sha256_block_তথ্য_order(শূন্য *ctx, ধ্রুবক শূন্য *in, size_t অঙ্ক);

শূন্য sha256_block_তথ্য_order(শূন্য *ctx, ধ্রুবক শূন্য *in, size_t অঙ্ক)
{
    যদি (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_block_তথ্য_order_lsx(ctx, in, অঙ্ক);
    } অন্যথা {
        sha256_block_তথ্য_order_la64v100(ctx, in, অঙ্ক);
    }
}

শূন্য sha512_block_তথ্য_order_la64v100(শূন্য *ctx, ধ্রুবক শূন্য *in, size_t অঙ্ক);
শূন্য sha512_block_তথ্য_order_lsx(শূন্য *ctx, ধ্রুবক শূন্য *in, size_t অঙ্ক);
শূন্য sha512_block_তথ্য_order(শূন্য *ctx, ধ্রুবক শূন্য *in, size_t অঙ্ক);

শূন্য sha512_block_তথ্য_order(শূন্য *ctx, ধ্রুবক শূন্য *in, size_t অঙ্ক)
{
    যদি (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_block_তথ্য_order_lsx(ctx, in, অঙ্ক);
    } অন্যথা {
        sha512_block_তথ্য_order_la64v100(ctx, in, অঙ্ক);
    }
}
