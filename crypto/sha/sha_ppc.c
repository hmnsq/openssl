/*
 * Copyright 2009-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#അന്തര്ഭാവ "arch/ppc_arch.h"

ശൂന്യം sha256_block_p8(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *inp, size_t len);
ശൂന്യം sha256_block_ppc(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *inp, size_t len);
ശൂന്യം sha256_block_data_order(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *inp, size_t len);
ശൂന്യം sha256_block_data_order(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_block_p8(ctx, inp, len) : sha256_block_ppc(ctx, inp, len);
}

ശൂന്യം sha512_block_p8(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *inp, size_t len);
ശൂന്യം sha512_block_ppc(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *inp, size_t len);
ശൂന്യം sha512_block_data_order(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *inp, size_t len);
ശൂന്യം sha512_block_data_order(ശൂന്യം *ctx, സ്ഥിരം ശൂന്യം *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_block_p8(ctx, inp, len) : sha512_block_ppc(ctx, inp, len);
}
