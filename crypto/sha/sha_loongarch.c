/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#ਅਨ੍ਤਰ੍ਭਾਵ "arch/loongarch_arch.h"

ਖਾਲੀ sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_la64v100(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);
ਖਾਲੀ sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_lsx(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);
ਖਾਲੀ sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);

ਖਾਲੀ sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ)
{
    ਜੇ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_lsx(ctx, ਵਿੱਚ, ਅੰਕ);
    } ਨਹੀਂਤਾਂ {
        sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_la64v100(ctx, ਵਿੱਚ, ਅੰਕ);
    }
}

ਖਾਲੀ sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_la64v100(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);
ਖਾਲੀ sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_lsx(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);
ਖਾਲੀ sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);

ਖਾਲੀ sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ)
{
    ਜੇ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_lsx(ctx, ਵਿੱਚ, ਅੰਕ);
    } ਨਹੀਂਤਾਂ {
        sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_la64v100(ctx, ਵਿੱਚ, ਅੰਕ);
    }
}
