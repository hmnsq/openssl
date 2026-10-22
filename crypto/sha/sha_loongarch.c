/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#ಅನ್ತರ್ಭಾವ "arch/loongarch_arch.h"

ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_la64v100(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_lsx(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);

ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ)
{
    ಆದರೆ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_lsx(ctx, ಒಳ, ಅಂಕೆ);
    } ಇಲ್ಲದಿದ್ದರೆ {
        sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_la64v100(ctx, ಒಳ, ಅಂಕೆ);
    }
}

ಶೂನ್ಯ sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_la64v100(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_lsx(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);
ಶೂನ್ಯ sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ);

ಶೂನ್ಯ sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಒಳ, size_t ಅಂಕೆ)
{
    ಆದರೆ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_lsx(ctx, ಒಳ, ಅಂಕೆ);
    } ಇಲ್ಲದಿದ್ದರೆ {
        sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ_la64v100(ctx, ಒಳ, ಅಂಕೆ);
    }
}
