/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن <openssl/opensslconf.h>
#ضمن <openssl/sha.h>
#ضمن "arch/loongarch_arch.h"

فراغ sha256_بلاڪ_معلومات_ترتيب_la64v100(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);
فراغ sha256_بلاڪ_معلومات_ترتيب_lsx(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);
فراغ sha256_بلاڪ_معلومات_ترتيب(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);

فراغ sha256_بلاڪ_معلومات_ترتيب(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ)
{
    إذا (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_بلاڪ_معلومات_ترتيب_lsx(ctx, اندريون, انگ);
    } وإلا {
        sha256_بلاڪ_معلومات_ترتيب_la64v100(ctx, اندريون, انگ);
    }
}

فراغ sha512_بلاڪ_معلومات_ترتيب_la64v100(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);
فراغ sha512_بلاڪ_معلومات_ترتيب_lsx(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);
فراغ sha512_بلاڪ_معلومات_ترتيب(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ);

فراغ sha512_بلاڪ_معلومات_ترتيب(فراغ *ctx, ثابت فراغ *اندريون, size_t انگ)
{
    إذا (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_بلاڪ_معلومات_ترتيب_lsx(ctx, اندريون, انگ);
    } وإلا {
        sha512_بلاڪ_معلومات_ترتيب_la64v100(ctx, اندريون, انگ);
    }
}
