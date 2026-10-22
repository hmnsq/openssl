/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव <openssl/opensslconf.h>
#अन्तर्भाव <openssl/sha.h>
#अन्तर्भाव "arch/loongarch_arch.h"

शून्य sha256_block_data_order_la64v100(शून्य *ctx, ध्रुव शून्य *in, size_t अङ्कः);
शून्य sha256_block_data_order_lsx(शून्य *ctx, ध्रुव शून्य *in, size_t अङ्कः);
शून्य sha256_block_data_order(शून्य *ctx, ध्रुव शून्य *in, size_t अङ्कः);

शून्य sha256_block_data_order(शून्य *ctx, ध्रुव शून्य *in, size_t अङ्कः)
{
    जइ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_block_data_order_lsx(ctx, in, अङ्कः);
    } अण्णहा {
        sha256_block_data_order_la64v100(ctx, in, अङ्कः);
    }
}

शून्य sha512_block_data_order_la64v100(शून्य *ctx, ध्रुव शून्य *in, size_t अङ्कः);
शून्य sha512_block_data_order_lsx(शून्य *ctx, ध्रुव शून्य *in, size_t अङ्कः);
शून्य sha512_block_data_order(शून्य *ctx, ध्रुव शून्य *in, size_t अङ्कः);

शून्य sha512_block_data_order(शून्य *ctx, ध्रुव शून्य *in, size_t अङ्कः)
{
    जइ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_block_data_order_lsx(ctx, in, अङ्कः);
    } अण्णहा {
        sha512_block_data_order_la64v100(ctx, in, अङ्कः);
    }
}
