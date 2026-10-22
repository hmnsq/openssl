/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ <openssl/opensslconf.h>
#അന്തര്ഭാവ <openssl/sha.h>
#അന്തര്ഭാവ "arch/loongarch_arch.h"

ശൂന്യം sha256_block_data_order_la64v100(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);
ശൂന്യം sha256_block_data_order_lsx(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);
ശൂന്യം sha256_block_data_order(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);

ശൂന്യം sha256_block_data_order(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം)
{
    എങ്കിൽ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha256_block_data_order_lsx(ctx, in, അക്കം);
    } അല്ലെങ്കിൽ {
        sha256_block_data_order_la64v100(ctx, in, അക്കം);
    }
}

ശൂന്യം sha512_block_data_order_la64v100(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);
ശൂന്യം sha512_block_data_order_lsx(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);
ശൂന്യം sha512_block_data_order(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);

ശൂന്യം sha512_block_data_order(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം)
{
    എങ്കിൽ (OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX) {
        sha512_block_data_order_lsx(ctx, in, അക്കം);
    } അല്ലെങ്കിൽ {
        sha512_block_data_order_la64v100(ctx, in, അക്കം);
    }
}
