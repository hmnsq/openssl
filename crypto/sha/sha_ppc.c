/*
 * Copyright 2009-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ <openssl/opensslconf.h>
#অন্তর্ভাৱ <openssl/sha.h>
#অন্তর্ভাৱ "arch/ppc_arch.h"

শূন্য sha256_block_p8(শূন্য *ctx, ধ্রুৱ শূন্য *inp, size_t len);
শূন্য sha256_block_ppc(শূন্য *ctx, ধ্রুৱ শূন্য *inp, size_t len);
শূন্য sha256_block_data_order(শূন্য *ctx, ধ্রুৱ শূন্য *inp, size_t len);
শূন্য sha256_block_data_order(শূন্য *ctx, ধ্রুৱ শূন্য *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_block_p8(ctx, inp, len) : sha256_block_ppc(ctx, inp, len);
}

শূন্য sha512_block_p8(শূন্য *ctx, ধ্রুৱ শূন্য *inp, size_t len);
শূন্য sha512_block_ppc(শূন্য *ctx, ধ্রুৱ শূন্য *inp, size_t len);
শূন্য sha512_block_data_order(শূন্য *ctx, ধ্রুৱ শূন্য *inp, size_t len);
শূন্য sha512_block_data_order(শূন্য *ctx, ধ্রুৱ শূন্য *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_block_p8(ctx, inp, len) : sha512_block_ppc(ctx, inp, len);
}
