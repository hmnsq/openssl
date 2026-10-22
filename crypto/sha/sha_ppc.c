/*
 * Copyright 2009-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ <openssl/opensslconf.h>
#અન્તર્ભાવ <openssl/sha.h>
#અન્તર્ભાવ "arch/ppc_arch.h"

શૂન્ય sha256_block_p8(શૂન્ય *ctx, અચલ શૂન્ય *inp, size_t len);
શૂન્ય sha256_block_ppc(શૂન્ય *ctx, અચલ શૂન્ય *inp, size_t len);
શૂન્ય sha256_block_data_order(શૂન્ય *ctx, અચલ શૂન્ય *inp, size_t len);
શૂન્ય sha256_block_data_order(શૂન્ય *ctx, અચલ શૂન્ય *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha256_block_p8(ctx, inp, len) : sha256_block_ppc(ctx, inp, len);
}

શૂન્ય sha512_block_p8(શૂન્ય *ctx, અચલ શૂન્ય *inp, size_t len);
શૂન્ય sha512_block_ppc(શૂન્ય *ctx, અચલ શૂન્ય *inp, size_t len);
શૂન્ય sha512_block_data_order(શૂન્ય *ctx, અચલ શૂન્ય *inp, size_t len);
શૂન્ય sha512_block_data_order(શૂન્ય *ctx, અચલ શૂન્ય *inp, size_t len)
{
    OPENSSL_ppccap_P &PPC_CRYPTO207 ? sha512_block_p8(ctx, inp, len) : sha512_block_ppc(ctx, inp, len);
}
