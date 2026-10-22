/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#ਅਨ੍ਤਰ੍ਭਾਵ "arch/riscv_arch.h"

ਖਾਲੀ sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_zvkb_zvknha_or_zvknhb(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ,
    size_t ਅੰਕ);
ਖਾਲੀ sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_zbb(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);
ਖਾਲੀ sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_riscv64(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);
ਖਾਲੀ sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);

ਖਾਲੀ sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ)
{
    ਜੇ (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_zvkb_zvknha_or_zvknhb(ctx, ਵਿੱਚ, ਅੰਕ);
    } ਨਹੀਂਤਾਂ ਜੇ (RISCV_HAS_ZBB()) {
        sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_zbb(ctx, ਵਿੱਚ, ਅੰਕ);
    } ਨਹੀਂਤਾਂ {
        sha256_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_riscv64(ctx, ਵਿੱਚ, ਅੰਕ);
    }
}

ਖਾਲੀ sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_zvkb_zvknhb(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);
ਖਾਲੀ sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_zbb(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);
ਖਾਲੀ sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_c(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);
ਖਾਲੀ sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ);

ਖਾਲੀ sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ(ਖਾਲੀ *ctx, ਅਚਲ ਖਾਲੀ *ਵਿੱਚ, size_t ਅੰਕ)
{
    ਜੇ (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_zvkb_zvknhb(ctx, ਵਿੱਚ, ਅੰਕ);
    } ਨਹੀਂਤਾਂ ਜੇ (RISCV_HAS_ZBB()) {
        sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_zbb(ctx, ਵਿੱਚ, ਅੰਕ);
    } ਨਹੀਂਤਾਂ {
        sha512_ਖੰਡ_ਅੰਕੜੇ_ਕ੍ਰਮ_c(ctx, ਵਿੱਚ, ਅੰਕ);
    }
}
