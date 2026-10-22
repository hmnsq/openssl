/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#അന്തര്ഭാവ "arch/riscv_arch.h"

ശൂന്യം sha256_block_data_order_zvkb_zvknha_or_zvknhb(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in,
    size_t അക്കം);
ശൂന്യം sha256_block_data_order_zbb(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);
ശൂന്യം sha256_block_data_order_riscv64(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);
ശൂന്യം sha256_block_data_order(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);

ശൂന്യം sha256_block_data_order(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം)
{
    എങ്കിൽ (RISCV_HAS_ZVKB() && (RISCV_HAS_ZVKNHA() || RISCV_HAS_ZVKNHB()) && riscv_vlen() >= 128) {
        sha256_block_data_order_zvkb_zvknha_or_zvknhb(ctx, in, അക്കം);
    } അല്ലെങ്കിൽ എങ്കിൽ (RISCV_HAS_ZBB()) {
        sha256_block_data_order_zbb(ctx, in, അക്കം);
    } അല്ലെങ്കിൽ {
        sha256_block_data_order_riscv64(ctx, in, അക്കം);
    }
}

ശൂന്യം sha512_block_data_order_zvkb_zvknhb(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);
ശൂന്യം sha512_block_data_order_zbb(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);
ശൂന്യം sha512_block_data_order_c(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);
ശൂന്യം sha512_block_data_order(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം);

ശൂന്യം sha512_block_data_order(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *in, size_t അക്കം)
{
    എങ്കിൽ (RISCV_HAS_ZVKB_AND_ZVKNHB() && riscv_vlen() >= 128) {
        sha512_block_data_order_zvkb_zvknhb(ctx, in, അക്കം);
    } അല്ലെങ്കിൽ എങ്കിൽ (RISCV_HAS_ZBB()) {
        sha512_block_data_order_zbb(ctx, in, അക്കം);
    } അല്ലെങ്കിൽ {
        sha512_block_data_order_c(ctx, in, അക്കം);
    }
}
