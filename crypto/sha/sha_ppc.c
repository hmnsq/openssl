/*
 * Copyright 2009-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ <openssl/opensslconf.h>
#ଅନ୍ତର୍ଭାଵ <openssl/sha.h>
#ଅନ୍ତର୍ଭାଵ "arch/ppc_arch.h"

ଶୂନ୍ୟ sha256_block_p8(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *inp, size_t len);
ଶୂନ୍ୟ sha256_block_ppc(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *inp, size_t len);
ଶୂନ୍ୟ sha256_block_data_order(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *inp, size_t len);
ଶୂନ୍ୟ sha256_block_data_order(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_block_p8(ctx, inp, len) : sha256_block_ppc(ctx, inp, len);
}

ଶୂନ୍ୟ sha512_block_p8(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *inp, size_t len);
ଶୂନ୍ୟ sha512_block_ppc(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *inp, size_t len);
ଶୂନ୍ୟ sha512_block_data_order(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *inp, size_t len);
ଶୂନ୍ୟ sha512_block_data_order(ଶୂନ୍ୟ *ctx, ଅଚଳ ଶୂନ୍ୟ *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_block_p8(ctx, inp, len) : sha512_block_ppc(ctx, inp, len);
}
