/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <openssl/opensslconf.h>
#ಅನ್ತರ್ಭಾವ <openssl/sha.h>
#ಅನ್ತರ್ಭಾವ "arch/riscv_arch.h"

ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_zvkb_zvknha_or_zvknhb(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ,
    size_t ಅಂಕೆ);
ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_zbb(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_riscv64(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);

ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ)
{
    ಆದರೆ (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_zvkb_zvknha_or_zvknhb(ctx, ಒಳ, ಅಂಕೆ);
    } ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (RISCV_HAS_ZBB()) {
        sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_zbb(ctx, ಒಳ, ಅಂಕೆ);
    } ಇಲ್ಲದಿದ್ದರೆ {
        sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_riscv64(ctx, ಒಳ, ಅಂಕೆ);
    }
}

ಶೂನ್ಯ sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_zvkb_zvknhb(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_zbb(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_c(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);

ಶೂನ್ಯ sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ)
{
    ಆದರೆ (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_zvkb_zvknhb(ctx, ಒಳ, ಅಂಕೆ);
    } ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (RISCV_HAS_ZBB()) {
        sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_zbb(ctx, ಒಳ, ಅಂಕೆ);
    } ಇಲ್ಲದಿದ್ದರೆ {
        sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_c(ctx, ಒಳ, ಅಂಕೆ);
    }
}
