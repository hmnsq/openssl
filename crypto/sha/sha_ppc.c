/*
 * Copyright 2009-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#ಅನ್ತರ್ಭಾವ "arch/ppc_arch.h"

ಶೂನ್ಯ sha256_ಖಂಡ_p8(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *inp, size_t len);
ಶೂನ್ಯ sha256_ಖಂಡ_ppc(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *inp, size_t len);
ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *inp, size_t len);
ಶೂನ್ಯ sha256_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_ಖಂಡ_p8(ctx, inp, len) : sha256_ಖಂಡ_ppc(ctx, inp, len);
}

ಶೂನ್ಯ sha512_ಖಂಡ_p8(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *inp, size_t len);
ಶೂನ್ಯ sha512_ಖಂಡ_ppc(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *inp, size_t len);
ಶೂನ್ಯ sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *inp, size_t len);
ಶೂನ್ಯ sha512_ಖಂಡ_ದತ್ತಾಂಶ_ಕ್ರಮ(ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_ಖಂಡ_p8(ctx, inp, len) : sha512_ಖಂಡ_ppc(ctx, inp, len);
}
