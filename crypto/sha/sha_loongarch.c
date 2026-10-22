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

فراغ sha256_بلاک_معلومات_ترتیب_la64v100(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);
فراغ sha256_بلاک_معلومات_ترتیب_lsx(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);
فراغ sha256_بلاک_معلومات_ترتیب(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);

فراغ sha256_بلاک_معلومات_ترتیب(فراغ *ctx, ثابت فراغ *دننه, size_t عدد)
{
    إذا (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_بلاک_معلومات_ترتیب_lsx(ctx, دننه, عدد);
    } وإلا {
        sha256_بلاک_معلومات_ترتیب_la64v100(ctx, دننه, عدد);
    }
}

فراغ sha512_بلاک_معلومات_ترتیب_la64v100(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);
فراغ sha512_بلاک_معلومات_ترتیب_lsx(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);
فراغ sha512_بلاک_معلومات_ترتیب(فراغ *ctx, ثابت فراغ *دننه, size_t عدد);

فراغ sha512_بلاک_معلومات_ترتیب(فراغ *ctx, ثابت فراغ *دننه, size_t عدد)
{
    إذا (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_بلاک_معلومات_ترتیب_lsx(ctx, دننه, عدد);
    } وإلا {
        sha512_بلاک_معلومات_ترتیب_la64v100(ctx, دننه, عدد);
    }
}
