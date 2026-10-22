/*
 * Copyright 2009-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/opensslconf.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/sha.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "arch/ppc_arch.h"

ਖਾਲੀ sha256_ਖੰਡ_p8(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *inp, size_t len);
ਖਾਲੀ sha256_ਖੰਡ_ppc(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *inp, size_t len);
ਖਾਲੀ sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *inp, size_t len);
ਖਾਲੀ sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_ਖੰਡ_p8(ctx, inp, len) : sha256_ਖੰਡ_ppc(ctx, inp, len);
}

ਖਾਲੀ sha512_ਖੰਡ_p8(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *inp, size_t len);
ਖਾਲੀ sha512_ਖੰਡ_ppc(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *inp, size_t len);
ਖਾਲੀ sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *inp, size_t len);
ਖਾਲੀ sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_ਖੰਡ_p8(ctx, inp, len) : sha512_ਖੰਡ_ppc(ctx, inp, len);
}
