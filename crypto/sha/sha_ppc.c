/*
 * Copyright 2009-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#ضمن "arch/ppc_arch.h"

فراغ sha256_بلاڪ_p8(فراغ *ctx, ثابت فراغ *inp, size_t len);
فراغ sha256_بلاڪ_ppc(فراغ *ctx, ثابت فراغ *inp, size_t len);
فراغ sha256_بلاڪ_معلومات_ترتيب(فراغ *ctx, ثابت فراغ *inp, size_t len);
فراغ sha256_بلاڪ_معلومات_ترتيب(فراغ *ctx, ثابت فراغ *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_بلاڪ_p8(ctx, inp, len) : sha256_بلاڪ_ppc(ctx, inp, len);
}

فراغ sha512_بلاڪ_p8(فراغ *ctx, ثابت فراغ *inp, size_t len);
فراغ sha512_بلاڪ_ppc(فراغ *ctx, ثابت فراغ *inp, size_t len);
فراغ sha512_بلاڪ_معلومات_ترتيب(فراغ *ctx, ثابت فراغ *inp, size_t len);
فراغ sha512_بلاڪ_معلومات_ترتيب(فراغ *ctx, ثابت فراغ *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_بلاڪ_p8(ctx, inp, len) : sha512_بلاڪ_ppc(ctx, inp, len);
}
